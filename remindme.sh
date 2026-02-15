#!/usr/bin/env bash

osascript <<'END'
use framework "Foundation"
use scripting additions

-- Helper: Replace text (Foundation)
on replaceText(findText, replaceWith, sourceText)
    set nsSource to current application's NSString's stringWithString:sourceText
    set nsResult to nsSource's stringByReplacingOccurrencesOfString:findText withString:replaceWith
    return nsResult as text
end replaceText

-- Helper: Extract date using Data Detectors
on extractDateFromText(theString)
    set theDetector to current application's NSDataDetector's dataDetectorWithTypes:(current application's NSTextCheckingTypeDate) |error|:(missing value)
    set theMatches to theDetector's matchesInString:theString options:0 range:{location:0, |length|:length of theString}

    if (count of theMatches) > 0 then
        return (item 1 of theMatches)'s |date|() as date
    else
        return missing value
    end if
end extractDateFromText

-- Main
set targetListName to "Personal"
set rawText to the clipboard as text

-- Trim whitespace/newlines
set nsString to current application's NSString's stringWithString:rawText
set rawText to (nsString's stringByTrimmingCharactersInSet:(current application's NSCharacterSet's whitespaceAndNewlineCharacterSet)) as text

if rawText is "" then
    display notification "Clipboard is empty" with title "Reminder not created"
    return
end if

-- Parse date from normalized text
set parsedDate to extractDateFromText(normalizedText)

-- Fallback: today at 23:59:59
if parsedDate is missing value then
    set parsedDate to current date
    set hours of parsedDate to 23
    set minutes of parsedDate to 59
    set seconds of parsedDate to 59
end if

-- Alert: 1 day before due date
set nowDate to current date
set alertDate to parsedDate - (1 * days)

-- Guard: if alert time is in the past (or now), bump it to 1 minute from now
if alertDate is less than or equal to nowDate then
    set alertDate to nowDate + 60
end if

-- Create reminder (set due date + remind me date)
tell application "Reminders"
    if not (exists list targetListName) then
        display notification "List 'Personal' not found" with title "Reminder not created"
        return
    end if

    tell list targetListName
        make new reminder with properties {name:normalizedText, due date:parsedDate, remind me date:alertDate}
    end tell
end tell

-- Success notification (safe formatting)
set notificationText to "“" & normalizedText & "”" & return & ¬
    "Due: " & (parsedDate as string) & return & ¬
    "Alert: " & (alertDate as string)

display notification notificationText with title "✅ Reminder created"

END
