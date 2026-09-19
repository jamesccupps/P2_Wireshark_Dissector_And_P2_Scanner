"""
object_factory.py — Build bacpypes3 objects from manifest entries.

Maps APOGEE engineering unit strings (from the scanner's embedded TEC
application catalog) to BACnet EngineeringUnits enum values. Anything unknown
falls back to noUnits — the description still carries the original APOGEE unit
string for human readers, so nothing is lost, only unlabelled.
"""
from __future__ import annotations

import logging
from typing import Optional

from bacpypes3.basetypes import EngineeringUnits, Reliability, EventState
from bacpypes3.local.analog import AnalogInputObject, AnalogValueObject
from bacpypes3.local.binary import BinaryInputObject, BinaryValueObject

from .manifest import PointEntry

log = logging.getLogger(__name__)


# APOGEE unit string → BACnet EngineeringUnits enum.
#
# Checked against the scanner's embedded catalog: this map resolves 99.2% of
# unit-string occurrences across its 1,070 applications. Anything not in it
# falls back to noUnits but keeps the original string in the object
# description.
#
# Adding an entry is cheap and safe; MIS-mapping one is not, so a unit whose
# dimension is ambiguous (see "DEG" below) stays unmapped on purpose.
_UNIT_MAP = {
    # Temperature
    "DEG F": EngineeringUnits.degreesFahrenheit,
    "DEGF": EngineeringUnits.degreesFahrenheit,
    "F": EngineeringUnits.degreesFahrenheit,
    "DEG C": EngineeringUnits.degreesCelsius,
    "DEGC": EngineeringUnits.degreesCelsius,

    # "DEG" is deliberately NOT mapped to a temperature or to an angle.
    # In the TEC catalog it appears 302 times, mostly on ZONE TEMP, OCC CLG SP,
    # DISCHRG TEMP and HOST OA TEMP -- temperatures -- but also on POS GAS ACT
    # and its siblings, which are actuator positions in real degrees of angle.
    # One string, two dimensions. And even for the temperatures, Fahrenheit vs
    # Celsius depends on the panel's si_units flag, which is runtime state and
    # not knowable here. An earlier edition mapped it to degreesAngular, which
    # is wrong for roughly nine uses in ten.
    "DEG": EngineeringUnits.noUnits,
    "DEGREE": EngineeringUnits.degreesAngular,

    # Pressure
    "PSI": EngineeringUnits.poundsForcePerSquareInch,
    "PSIG": EngineeringUnits.poundsForcePerSquareInch,
    "INWC": EngineeringUnits.inchesOfWater,
    "IN WC": EngineeringUnits.inchesOfWater,
    "H2O": EngineeringUnits.inchesOfWater,
    "INHG": EngineeringUnits.inchesOfMercury,
    "KPA": EngineeringUnits.kilopascals,
    "PA": EngineeringUnits.pascals,
    "BAR": EngineeringUnits.bars,
    "MBAR": EngineeringUnits.millibars,

    # Flow
    "CFM": EngineeringUnits.cubicFeetPerMinute,
    "GPM": EngineeringUnits.usGallonsPerMinute,
    "GPH": EngineeringUnits.usGallonsPerHour,
    "FPM": EngineeringUnits.feetPerMinute,
    "FPS": EngineeringUnits.feetPerSecond,
    "MPS": EngineeringUnits.metersPerSecond,
    "L/S": EngineeringUnits.litersPerSecond,
    "LPS": EngineeringUnits.litersPerSecond,
    "LPM": EngineeringUnits.litersPerMinute,
    "M3/H": EngineeringUnits.cubicMetersPerHour,
    "M3PH": EngineeringUnits.cubicMetersPerHour,

    # Volume
    "CUFT": EngineeringUnits.cubicFeet,
    "CU FT": EngineeringUnits.cubicFeet,
    "CF": EngineeringUnits.cubicFeet,
    "GAL": EngineeringUnits.usGallons,

    # Power / energy
    "KW": EngineeringUnits.kilowatts,
    "W": EngineeringUnits.watts,
    "MW": EngineeringUnits.megawatts,
    "KWH": EngineeringUnits.kilowattHours,
    "WH": EngineeringUnits.wattHours,
    "MWH": EngineeringUnits.megawattHours,
    "BTU": EngineeringUnits.btus,
    "BTU/H": EngineeringUnits.btusPerHour,
    "MBH": EngineeringUnits.kiloBtusPerHour,
    "TON": EngineeringUnits.tonsRefrigeration,
    "TONS": EngineeringUnits.tonsRefrigeration,
    "BTUPLB": EngineeringUnits.btusPerPound,
    "BTUpLB": EngineeringUnits.btusPerPound,

    # Electrical
    "V": EngineeringUnits.volts,
    "VOLTS": EngineeringUnits.volts,
    "VAC": EngineeringUnits.volts,
    "VDC": EngineeringUnits.volts,
    "A": EngineeringUnits.amperes,
    "AMP": EngineeringUnits.amperes,
    "AMPS": EngineeringUnits.amperes,
    "ADC": EngineeringUnits.amperes,
    "MA": EngineeringUnits.milliamperes,

    # Frequency / rotational
    "HZ": EngineeringUnits.hertz,
    "HERTZ": EngineeringUnits.hertz,
    "RPM": EngineeringUnits.revolutionsPerMinute,
    # BACnet has no revolutionsPerSecond. hertz is dimensionally exact
    # (1 rev/s = 1 s-1 = 1 Hz). An earlier edition mapped this to
    # revolutionsPerMinute "as the closest match available", which is a factor
    # of sixty, not a close match. RPS does not occur in the shipped catalog,
    # so this has always been latent rather than active.
    "RPS": EngineeringUnits.hertz,

    # Time
    "S": EngineeringUnits.seconds,
    "SEC": EngineeringUnits.seconds,
    "SECS": EngineeringUnits.seconds,
    "MIN": EngineeringUnits.minutes,
    "MINS": EngineeringUnits.minutes,
    "HOUR": EngineeringUnits.hours,
    "HOURS": EngineeringUnits.hours,
    "H": EngineeringUnits.hours,
    "HHMM": EngineeringUnits.noUnits,    # APOGEE time-of-day; no BACnet equivalent
    "DAY": EngineeringUnits.days,
    "DAYS": EngineeringUnits.days,
    "MONTH": EngineeringUnits.months,
    "MONTHS": EngineeringUnits.months,
    "YEAR": EngineeringUnits.years,
    "YEARS": EngineeringUnits.years,
    "10K HR": EngineeringUnits.hours,  # tens-of-thousand-hours counter

    # Concentration / quality
    "PPM": EngineeringUnits.partsPerMillion,
    "PPB": EngineeringUnits.partsPerBillion,
    "%": EngineeringUnits.percent,
    "PCT": EngineeringUnits.percent,
    "PCNT": EngineeringUnits.percent,
    "%RH": EngineeringUnits.percentRelativeHumidity,
    "RH": EngineeringUnits.percentRelativeHumidity,

    # Counts and dimensionless
    "CNTS": EngineeringUnits.noUnits,
    "COUNTS": EngineeringUnits.noUnits,
    "CYCLES": EngineeringUnits.noUnits,
    "PULSES": EngineeringUnits.noUnits,
    "ERR CD": EngineeringUnits.noUnits,
    "STATE": EngineeringUnits.noUnits,
    "STARTS": EngineeringUnits.noUnits,
    "YYMMDD": EngineeringUnits.noUnits,      # packed date, no BACnet equivalent

    # ---- spellings the shipped catalog actually uses --------------------
    # Added after checking the map against the scanner's embedded catalog:
    # 50 of 115 distinct unit strings were mapped, and the unmapped ones were
    # the COMMON ones. `HRS` alone occurs 901 times and was falling through to
    # noUnits. Ordered by catalog frequency.
    "HRS": EngineeringUnits.hours,                          # 901
    "HR": EngineeringUnits.hours,                           # 74
    "10KHRS": EngineeringUnits.hours,
    "INCHES": EngineeringUnits.inches,                      # 599
    "IN": EngineeringUnits.inches,
    "SQ. FT": EngineeringUnits.squareFeet,                  # 336
    "SQFT": EngineeringUnits.squareFeet,                    # 179
    "SQ FT": EngineeringUnits.squareFeet,
    "SQINCH": EngineeringUnits.squareInches,                # 27
    "SQ IN": EngineeringUnits.squareInches,
    "KVAR": EngineeringUnits.kilovoltAmperesReactive,       # 139
    "KVA": EngineeringUnits.kilovoltAmperes,                # 136
    "VA": EngineeringUnits.voltAmperes,
    "KVARH": EngineeringUnits.kilovoltAmpereHoursReactive,  # 36
    "KVAR H": EngineeringUnits.kilovoltAmpereHoursReactive,
    "VARH": EngineeringUnits.voltAmpereHoursReactive,       # 37
    "KVA H": EngineeringUnits.kilovoltAmpereHours,          # 21
    "KVAH": EngineeringUnits.kilovoltAmpereHours,
    "KW H": EngineeringUnits.kilowattHours,                 # 21
    "PCT RH": EngineeringUnits.percentRelativeHumidity,     # 108
    "PCTRH": EngineeringUnits.percentRelativeHumidity,      # 108
    "PERCNT": EngineeringUnits.percent,                     # 83
    "PCTFLA": EngineeringUnits.percent,                     # 72, % of full-load amps
    "MINUTE": EngineeringUnits.minutes,                     # 49
    "IN H2O": EngineeringUnits.inchesOfWater,               # 31
    "CFH": EngineeringUnits.cubicFeetPerHour,
    "LBS": EngineeringUnits.poundsMass,
    "LB/HR": EngineeringUnits.poundsMassPerHour,
    "LBS/HR": EngineeringUnits.poundsMassPerHour,
}


def map_units(apogee_unit: Optional[str]) -> EngineeringUnits:
    """APOGEE engineering-unit string → BACnet EngineeringUnits enum value."""
    if not apogee_unit:
        return EngineeringUnits.noUnits
    key = apogee_unit.strip().upper()
    return _UNIT_MAP.get(key, EngineeringUnits.noUnits)


def build_object(entry: PointEntry):
    """
    Build a bacpypes3 object for one manifest entry.

    Returns the live object — the bridge holds it in its app and updates
    `presentValue`, `reliability`, `statusFlags`, `eventState` from the
    poller as readings come in.

    Initial state is intentionally `unreliable / communication-failure` —
    the bridge has not heard from the panel yet at startup. The first
    successful read clears it.
    """
    obj_id = (entry.bacnet_object_type, entry.bacnet_instance)
    obj_name = entry.object_name
    desc = entry.description
    obj_type = entry.bacnet_object_type

    if obj_type in ("analogInput", "analogValue"):
        units = map_units(entry.units)
        kwargs = dict(
            objectIdentifier=obj_id,
            objectName=obj_name,
            description=desc,
            presentValue=0.0,
            statusFlags=[0, 1, 0, 0],   # in-alarm, fault, overridden, oos
            eventState=EventState.normal,
            reliability=Reliability.communicationFailure,
            outOfService=False,
            units=units,
            covIncrement=0.1,
        )
        cls = AnalogInputObject if obj_type == "analogInput" else AnalogValueObject
        return cls(**kwargs)

    if obj_type in ("binaryInput", "binaryValue"):
        kwargs = dict(
            objectIdentifier=obj_id,
            objectName=obj_name,
            description=desc,
            presentValue="inactive",
            statusFlags=[0, 1, 0, 0],
            eventState=EventState.normal,
            reliability=Reliability.communicationFailure,
            outOfService=False,
            inactiveText=entry.off_label or "OFF",
            activeText=entry.on_label or "ON",
        )
        cls = BinaryInputObject if obj_type == "binaryInput" else BinaryValueObject
        return cls(**kwargs)

    raise ValueError(f"Unknown BACnet object type: {obj_type!r}")
