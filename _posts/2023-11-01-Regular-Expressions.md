---
layout: post
title: Regular Expressions
date: 2023-11-01
tags: [Study Notes, Antisyphon]
---
>   Source: [Antisyphon Training](https://www.antisyphontraining.com/live-courses-catalog/regular-expressions-your-new-lifestyle-w-joff-thyer/)
>

# I. Vanilla Regular Expressions (RegEx)

### RegEx are like PACMAN

-   Successful matching of the pattern from left-to-right.
-   Sometimes implemented functions perform a single match of a pattern, and sometimes multiple matches of the same pattern.

### RegEx Character Sets/Classes

```bash
\w match single word character (A-Z,a-z,0-9, or _)
\d match a single digit 0-9
\s match a single space character (defined as space, tab, or newline)
\W match a single character that is NOT in the \w set 
\D match a single character that is NOT in the \d set
\S match a single character that is NOT in the \s set
\b word boundary match, bi-directional transition \w <-> \W
[A-F] match a single character in the range A to F inclusive (custom set) 
[\w!@] match a single characer in this custom set (word, !, and @)
[^A-Z] match a single character that is NOT in the range A to Z.
. match ANY single character (wildcard)
```

### RegEx Quantifiers

```bash
After any single character match, we can specify a quantifier!

? match the previous character 0 or 1 time (optional match)
* match the previous character 0 or more times
+ match the previous character 1 or more times
{x} match the previous character exactly "x" times
{x,y} match the previous character between x, and y times
```

##### Quantifier Example

How could we match a US Phone Number? (Format: 10 digits `NPA-NXX-XXXX`)

-   NPA = area code
-   NXX = subscriber code for local area code
-   Eg: 800-555-1212

Our ReGex could be

-   `\d\d\d-\d\d\d-\d\d\d\d`
-   `\d{3}-\d{3}-\d{4}`

##### Prevent Quantifiers from being greedy

-   We can add a modifier after the quantifier to STOP being so greedy
-   It is a `?` character in the pattern right after the `+` or `*`
-   Example: 
    -   Text String: `I love the sunlight in the spring. It makes me feel so alive! Please don't let it rain.`
    -   We want sentences that begins with capital letter, ends with punctuation character and can have any letter in between.
    -   `[A-Z].+[!?\.]`: This returns the whole text as a single match.
    -   `[A-Z].+?[!?\.]`: This returns three matches from the text.

### RegEx Anchors

-   `^` assert that the following characters in the pattern definition must match at the <u>beginning</u> of the string being processed
-   `$` assert that the preceding characters in the pattern definition must match at the <u>end</u> of the string being processed
-   Example:
    -   `^\d{4}-\d{2}-\d{2}` would match a string such as `2020-01-30` only at the beginning of the data being processed.

### RegEx Behaviour Modifiers

-   The following expressions when included in a pattern will change the behaviour of the RegEx pattern matching process.
    -   `(?i)`: disables case sensitivity when matching the pattern (ignore case)
    -   `(?m)`: match beyond the end of a line in a string (multiline)
    -   `(?s)`: the wildcard `.` will match line breaks also (dotall)

### RegEx Logical OR

-   Use parenthesis and the pipe symbol `|` to form a logical OR
-   Example: match the months of the year between 01 and 12
    -   `(?:0[1-9]|1[0-2])`

### RegEx Capturing Groups

-   Allows us to sub-group a part of the RegEx pattern match
-   `(\d{2})-(\d{2})-(\d{4})`
    -   Example: `28-02-2023` becomes `28`, `02`, `2023`
-   `(\w+)@(\w+\.\w+)`
    -   Example: `john@example.com` becomes `john`, `example.com`

### RegEx Meta Characters

-   What if we want to match a special meta character? Use backslash to escape the meta-character.
-   `[A-Z]\w\+\.` matches one uppercase, one or more word chars, and then EXACTLY a period character.

### Examples of RegEx

-   `0x[A-Fa-f0-9]+` matches any hexadecimal

-   `^4[0-9]{12}(?:[0-9]{3})?$` matches any VISA credit card number
    -   -   Beginning and end assertation with `^` and `$`
        -   Must start with 4 followed by 12 required digits `4[0-9]{12}`
        -   Group of three digits at end is optional `([0-9]{3})?`
        -   Capture group behaviour is disabled `?:`

-   `^(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12}$` matches any MasterCard credit card number
    -   Beginning and end assertation with `^` and `$`
    -   Start with `51` - `55`, then 2 digits `5[1-5][0-9]{2}`
    -   Start with `2221` - `2270` `222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720`
    -   12 additional digits `[0-9]{12}`
    -   Capture group behaviour is disabled `?:`

-   `(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)` matches any IPv4 address precisely

    -   Matches `250` - `255`

    -   Matches `200` - `249`

    -   Matches `0` - `199`

    -   Prior character match is optional

    -   ```bash
        # completely accurate match
        (?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}↵
        (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
        ```




# II. Linux RegEx



`grep --color -Po "(?i)(?<=href=['\"])https?://[^'\"]+(?=['\"])”`

disable case sensitivity
look behind for “href=[‘\”]” (single or double quote)
match anything that looks like a URL (with optional “s” for SSL/TLS)
look ahead for single or double quote

-   -o = show only nonempty parts of lines that match
