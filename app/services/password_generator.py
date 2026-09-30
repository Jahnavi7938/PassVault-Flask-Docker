"""Password generation. Everything here uses `secrets` (the OS CSPRNG), never `random`."""
import math
import secrets
import string

from app.services.security_service import label_for

UPPER = string.ascii_uppercase
LOWER = string.ascii_lowercase
DIGITS = string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{}:;,.?/~"
AMBIGUOUS = set("O0Il1")

# ~240 short, easy-to-type words, roughly 7.9 bits each.
WORDS = """
acorn adobe agate alder amber anvil apple arbor aspen atlas attic badge baker banjo barn basil beach
beam berry birch bison blaze bloom bluff boat bolt bonus brass bread brick bridge brook broom cabin
cable cadet camel candy canoe cargo cedar chalk charm chess chime cider civic clay cliff clock cloud
clover cobalt comet coral cotton crane crate creek crest crisp crown cubic curry daisy delta denim
depot dune eagle earth easel ember epoch fable falcon fancy fawn fern ferry fiddle field finch flint
flute focus forge fossil frost galaxy garden garlic gecko ginger glade glass globe gopher grain grape
gravel grove guitar habit harbor hazel heron hickory honey horizon hover humble icon igloo indigo
inlet iris island ivory jacket jade jasper jelly jungle kayak kettle kiosk kitten ladder lagoon lake
lantern laurel lemon lilac linen lotus lumber lunar magnet mango maple marble meadow melon mesa mint
mirror mocha moose mosaic moss mural nectar nickel noble north novel oak oasis ocean olive onyx opal
orbit orchid otter oyster paddle panda paper pearl pebble pepper piano pilot pine planet plum pond
poppy prairie prism pumpkin quartz quill quilt rabbit radar rain raven reef ribbon ridge river robin
rocket saddle safari sage salmon sand scout shell silver slate sleet solar spark spice spruce stone
storm sugar summit swift tango thistle thunder tiger timber tulip tundra umber valley velvet violet
walnut willow window winter wren yarrow yellow zebra zephyr zinc
""".split()
assert len(WORDS) == len(set(WORDS)), "duplicate word in list"
# Entropy is computed from the real list size, so the estimate stays honest.
_WORD_BITS = math.log2(len(WORDS))


def _result(password, entropy):
    entropy = round(entropy, 1)
    return {"password": password, "entropy": entropy, "strength": label_for(entropy),
            "score": min(100, round(entropy / 80 * 100))}


def generate_random(length=20, upper=True, lower=True, digits=True, symbols=True, exclude_ambiguous=False):
    if not 8 <= length <= 64:
        raise ValueError("Length must be between 8 and 64.")
    groups = [g for enabled, g in ((upper, UPPER), (lower, LOWER), (digits, DIGITS), (symbols, SYMBOLS)) if enabled]
    if exclude_ambiguous:
        groups = ["".join(c for c in g if c not in AMBIGUOUS) for g in groups]
    if not groups:
        raise ValueError("Pick at least one character type.")
    pool = "".join(groups)
    # One guaranteed character from every selected group, the rest from the whole pool, then shuffle.
    chars = [secrets.choice(g) for g in groups]
    chars += [secrets.choice(pool) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return _result("".join(chars), length * math.log2(len(pool)))


def generate_memorable(words=6, exclude_ambiguous=False):
    if not 3 <= words <= 8:
        raise ValueError("Use between 3 and 8 words.")
    picked = [secrets.choice(WORDS).capitalize() for _ in range(words)]
    digit_pool = [d for d in DIGITS if not (exclude_ambiguous and d in AMBIGUOUS)]
    number = "".join(secrets.choice(digit_pool) for _ in range(3))
    symbol = secrets.choice(SYMBOLS)
    entropy = words * _WORD_BITS + 3 * math.log2(len(digit_pool)) + math.log2(len(SYMBOLS))
    return _result("-".join(picked) + "-" + number + symbol, entropy)


def generate_pin(length=6, exclude_ambiguous=False):
    if not 4 <= length <= 12:
        raise ValueError("A PIN must be 4-12 digits.")
    pool = [d for d in DIGITS if not (exclude_ambiguous and d in AMBIGUOUS)]
    return _result("".join(secrets.choice(pool) for _ in range(length)), length * math.log2(len(pool)))


def _int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def generate(opts):
    """Entry point for the API. `opts` is the parsed JSON body. Raises ValueError on bad input."""
    mode = opts.get("mode", "random")
    amb = bool(opts.get("exclude_ambiguous", False))
    if mode == "memorable":
        return generate_memorable(_int(opts.get("words"), 6), amb)
    if mode == "pin":
        return generate_pin(_int(opts.get("length"), 6), amb)
    if mode == "random":
        return generate_random(
            _int(opts.get("length"), 20),
            bool(opts.get("upper", True)), bool(opts.get("lower", True)),
            bool(opts.get("digits", True)), bool(opts.get("symbols", True)), amb,
        )
    raise ValueError("Unknown mode.")
