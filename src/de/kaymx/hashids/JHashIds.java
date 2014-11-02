package de.kaymx.jhashids;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JHashIds {
    private static final String DEFAULT_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    private static final String DEFAULT_SALT = "";
    private static final String DEFAULT_SEPARATORS = "cfhistuCFHISTU";
    private static final double SEP_DIV_THRESHOLD = 3.5f;
    private static final int GUARD_DIV = 12;
    private static final int MIN_ALPHABET_LENGTH = 16;

    private final char[] usedSeparators;
    private final int minHashLength;
    private final char[] usedSalt;
    private final char[] usedAlphabet;
    private final char[] usedGuards;
    private final Pattern guardPattern;
    private final Pattern splitPattern;

    public JHashIds(String salt, Integer minHashLength, String alphabet) {
        this.usedSalt = salt == null || salt.isEmpty()
                ? DEFAULT_SALT.toCharArray()
                : salt.toCharArray();
        this.minHashLength = minHashLength;

        char[] prepUsedAlphabet = makeUniqueAlphabet(alphabet != null ? alphabet : DEFAULT_ALPHABET);
        char[] prepUsedSeparators = DEFAULT_SEPARATORS.toCharArray();

        if (prepUsedAlphabet.length < MIN_ALPHABET_LENGTH) {
            throw new RuntimeException("error: alphabet must contain at least X unique characters");
        }

        if (findCharInCharArray(prepUsedAlphabet, ' ') != -1) {
            throw new RuntimeException("error: alphabet cannot contain spaces");
        }

        for (int i = 0; i < prepUsedSeparators.length; ++i) {
            int pos = findCharInCharArray(prepUsedAlphabet, prepUsedSeparators[i]);
            if (pos == -1) {
                prepUsedSeparators[i] = ' ';
            } else {
                prepUsedAlphabet[pos] = ' ';
            }
        }

        prepUsedAlphabet = removeCharFromCharArray(prepUsedAlphabet, ' ');
        prepUsedSeparators = consistentShuffle(removeCharFromCharArray(prepUsedSeparators, ' '), usedSalt);

        if (prepUsedSeparators.length > 0 || prepUsedAlphabet.length / prepUsedSeparators.length > SEP_DIV_THRESHOLD) {
            int separatorsLength = Math.max((int) Math.ceil(prepUsedAlphabet.length / SEP_DIV_THRESHOLD), 2);

            if (separatorsLength > prepUsedSeparators.length) {
                int diff = separatorsLength - prepUsedSeparators.length;

                char[] newPrepUsedSeparators = Arrays.copyOf(prepUsedSeparators, prepUsedSeparators.length + diff);

                System.arraycopy(prepUsedAlphabet, 0, newPrepUsedSeparators, prepUsedSeparators.length, diff);
                prepUsedSeparators = newPrepUsedSeparators;
                prepUsedAlphabet = Arrays.copyOfRange(prepUsedAlphabet, diff, prepUsedAlphabet.length);
            } else {
                prepUsedSeparators = Arrays.copyOfRange(prepUsedSeparators, 0, separatorsLength);
            }
        }

        prepUsedAlphabet = consistentShuffle(prepUsedAlphabet, usedSalt);
        int guardCount = (int) Math.ceil((double) prepUsedAlphabet.length / GUARD_DIV);

        if (prepUsedAlphabet.length < 3) {
            this.usedGuards = Arrays.copyOf(prepUsedSeparators, guardCount);
            prepUsedSeparators = Arrays.copyOfRange(prepUsedSeparators, guardCount, prepUsedSeparators.length);
        } else {
            this.usedGuards = Arrays.copyOf(prepUsedAlphabet, guardCount);
            prepUsedAlphabet = Arrays.copyOfRange(prepUsedAlphabet, guardCount, prepUsedAlphabet.length);
        }

        this.usedAlphabet = prepUsedAlphabet;
        this.usedSeparators = prepUsedSeparators;

        String g = new String(usedGuards);
        String a = new String(usedAlphabet);
        String s = new String(usedSeparators);
        this.guardPattern = Pattern.compile("^([" + a + "]*[" + g + "])?([" + a + s + "]+)([" + g + "][" + a + "]*)?$");
        this.splitPattern = Pattern.compile("[" + s + "]");
    }

    private static char[] removeCharFromCharArray(char[] input, char removeChar) {
        int newArraySize = input.length;
        for (char c : input) {
            if (c == removeChar) {
                newArraySize--;
            }
        }

        char[] result = new char[newArraySize];

        int writePos = 0;
        for (char c : input) {
            if (c != removeChar) {
                result[writePos++] = c;
            }
        }

        return result;
    }

    private static char[] makeUniqueAlphabet(String alphabet) {
        LinkedHashSet<Character> characters = new LinkedHashSet<>();
        for (char c : alphabet.toCharArray()) {
            characters.add(c);
        }

        char[] result = new char[characters.size()];
        int pos = 0;
        for (Character character : characters) {
            result[pos++] = character;
        }

        return result;
    }

    private static int calcNumbersHashInt(long... numbers) {
        int numbersHashInt = 0;
        for (int i = 0; i < numbers.length; i++) {
            numbersHashInt += (numbers[i] % (i + 100));
        }
        return numbersHashInt;
    }

    public String encodeHex(String hex) {
        if (!hex.matches("^[0-9a-fA-F]+$"))
            return "";

        Matcher matcher = Pattern.compile("[\\w\\W]{1,12}").matcher(hex);
        List<Long> matched = new ArrayList<>();
        while (matcher.find()) {
            matched.add(Long.parseLong("1" + matcher.group(), 16));
        }
        long[] numbers = new long[matched.size()];

        for (int i = 0; i < matched.size(); i++) {
            numbers[i] = matched.get(i);
        }
        return encode(numbers);
    }

    public String decodeHex(String hashid) {
        long[] numbers = decode(hashid);

        StringBuilder sb = new StringBuilder();

        for (long number : numbers) {
            sb.append(Long.toHexString(number).substring(1));
        }
        return sb.toString();
    }

    public String encode(long... numbers) {
        if (0 == numbers.length) {
            return "";
        }

        for (long number : numbers) {
            if (number < 0) {
                return "";
            }
        }
        return _encode(numbers);
    }

    private String _encode(long[] numbers) {
        int numbersHashInt = calcNumbersHashInt(numbers);

        char alphabet[] = Arrays.copyOf(usedAlphabet, usedAlphabet.length);
        char lottery = alphabet[numbersHashInt % alphabet.length];
        StringBuilder resultBuilder = new StringBuilder("" + lottery);

        char[] buffer = new char[1 + usedSalt.length + usedAlphabet.length];
        buffer[0] = lottery;

        for (int i = 0; i != numbers.length; i++) {
            System.arraycopy(usedSalt, 0, buffer, 1, usedSalt.length);
            System.arraycopy(alphabet, 0, buffer, 1 + usedSalt.length, alphabet.length);
            alphabet = consistentShuffle(alphabet, Arrays.copyOfRange(buffer, 0, alphabet.length));

            char[] last = hash(numbers[i], alphabet);
            resultBuilder.append(last);

            if (i + 1 < numbers.length) {
                numbers[i] %= (last[0] + 1);
                int index = (int) (numbers[i] % usedSeparators.length);
                resultBuilder.append(usedSeparators[index]);
            }
        }

        char[] resultChars = resultBuilder.toString().toCharArray();

        int currentSize = resultChars.length;
        if (resultChars.length < minHashLength) {
            int hashPos = minHashLength - resultChars.length - (minHashLength - resultChars.length) / 2;
            char[] minResultSizeBuffer = new char[minHashLength];
            System.arraycopy(resultChars, 0, minResultSizeBuffer, hashPos, resultChars.length);

            int writeFrontPos = hashPos - 1;
            int writeEndPos = hashPos + resultChars.length;

            int guardIndex = (numbersHashInt + minResultSizeBuffer[hashPos]) % usedGuards.length;
            minResultSizeBuffer[writeFrontPos--] = usedGuards[guardIndex];
            currentSize++;

            if (writeEndPos < minResultSizeBuffer.length) {
                guardIndex = (numbersHashInt + minResultSizeBuffer[hashPos + 1]) % usedGuards.length;
                minResultSizeBuffer[writeEndPos++] = usedGuards[guardIndex];
                currentSize++;
            }

            int halfLength = usedAlphabet.length / 2;
            while (currentSize < minHashLength) {
                alphabet = consistentShuffle(alphabet, alphabet);
                int readFrontPos = (2 * halfLength) - 1;
                int readEndPos = 0;

                while (writeFrontPos >= 0 && readFrontPos >= halfLength) {
                    minResultSizeBuffer[writeFrontPos--] = alphabet[readFrontPos--];
                    currentSize++;
                }
                while (writeEndPos < minResultSizeBuffer.length && readEndPos < halfLength) {
                    minResultSizeBuffer[writeEndPos++] = alphabet[readEndPos++];
                    currentSize++;
                }
            }
            resultChars = minResultSizeBuffer;
        }

        return new String(resultChars);
    }

    public long[] decode(String input) {
        if (input == null || input.isEmpty()) {
            return new long[0];
        }
        return _decode(input);
    }

    private long[] _decode(String input) {
        Hashes hashes = getHashes(input);

        if (hashes != null) {
            char[] alphabet = Arrays.copyOf(usedAlphabet, usedAlphabet.length);
            long[] result = new long[hashes.hashes.length];

            char buffer[] = new char[1 + usedSalt.length + alphabet.length];
            System.arraycopy(usedSalt, 0, buffer, 1, usedSalt.length);
            buffer[0] = hashes.lottery;

            for (int i = 0; i < hashes.hashes.length; i++) {
                System.arraycopy(alphabet, 0, buffer, 1 + usedSalt.length, alphabet.length);
                alphabet = consistentShuffle(alphabet, Arrays.copyOfRange(buffer, 0, alphabet.length));
                result[i] = unhash(hashes.hashes[i].toCharArray(), alphabet);
            }
            return result;
        }

        return new long[0];
    }

    private Hashes getHashes(String input) {
        Matcher matcher = guardPattern.matcher(input);

        if (matcher.matches()) {
            String[] split = splitPattern.split(matcher.group(2));

            if (split.length > 0) {
                char lottery = split[0].charAt(0);
                split[0] = split[0].substring(1);
                return new Hashes(lottery, split);
            }
        }

        return null;
    }

    private static char[] hash(long input, char[] alphabet) {
        StringBuilder resultBuilder = new StringBuilder();

        do {
            resultBuilder.append(alphabet[(int) (input % alphabet.length)]);
            input = input / alphabet.length;
        }
        while (input != 0);

        return resultBuilder.reverse().toString().toCharArray();
    }

    private static long unhash(char[] input, char[] alphabet) {
        long number = 0;

        for (int i = 0; i < input.length; ++i) {
            int pos = findCharInCharArray(alphabet, input[i]);
            number += pos * (long) Math.pow(alphabet.length, input.length - i - 1);
        }

        return number;
    }

    private static int findCharInCharArray(char[] charArray, char c) {
        for (int i = 0; i < charArray.length; i++) {
            if (c == charArray[i]) {
                return i;
            }
        }
        return -1;
    }

    public static char[] consistentShuffle(char[] alphabet, char[] salt) {
        if (salt == null || salt.length == 0) {
            return alphabet;
        }

        char[] resultAlphabet = Arrays.copyOf(alphabet, alphabet.length);
        char[] tempAlphabet = new char[resultAlphabet.length];

        for (int i = resultAlphabet.length - 1, j, v = 0, p = 0; i > 0; i--, v++) {
            v %= salt.length;
            p += salt[v];
            j = (salt[v] + v + p) % i;

            tempAlphabet[j] = resultAlphabet[i];
            System.arraycopy(resultAlphabet, 0, tempAlphabet, 0, j);
            System.arraycopy(resultAlphabet, j + 1, tempAlphabet, j + 1, resultAlphabet.length - j - 1);

            resultAlphabet[i] = resultAlphabet[j];
            System.arraycopy(tempAlphabet, 0, resultAlphabet, 0, i);
            System.arraycopy(tempAlphabet, i + 1, resultAlphabet, i + 1, tempAlphabet.length - i - 1);
        }

        return resultAlphabet;
    }

    public String getVersion() {
        return "1.0.1";
    }

    private static class Hashes {
        private final char lottery;
        private final String[] hashes;

        private Hashes(char lottery, String[] hashes) {
            this.lottery = lottery;
            this.hashes = hashes;
        }
    }
}