#!/bin/bash

run() {
    local cmd="$1"
    local expected_output="$2"
    local expected_return_code="$3"
    local simpleOutputMode="${4:-false}"
    output=$(eval "$cmd"; r=$?; echo /; exit $r)
    local return_code=$?
    output=${output:0:-1}
    if [ "$output" != "$expected_output" ]; then
        echo "- FAIL:  '$cmd'"
        echo "  Expected output:  '$expected_output'"
        echo "  Actual output:    '$output'"
        return 1
    fi
    if [ "$return_code" != "$expected_return_code" ]; then
        echo "- FAIL:  '$cmd'"
        echo "  Expected return code:  '$expected_return_code'"
        echo "  Actual return code:    '$return_code'"
        return 1
    fi
    if [ "$simpleOutputMode" == true ]; then
        echo -ne "+"
        return
    else
        echo "+ PASS:  '$cmd'"
    fi
    return 0
}

getHashOf() {
    echo -ne "$1" | sha256sum | cut -d ' ' -f 1
}
nl=$'\n'

run "echo -ne \"zprava\" | ./kry -c" "d8305a064cd0f827df85ae5a7732bf25d578b746b8434871704e98cde3208ddf${nl}" 0
run "echo -ne \"zprava\" | ./kry -s -k heslo" "23158796a45a9392951d9a72dffd6a539b14a07832390b937b94a80ddb6dc18e${nl}" 0
run "echo -ne \"zprava\" | ./kry -v -k heslo -m 23158796a45a9392951d9a72dffd6a539b14a07832390b937b94a80ddb6dc18e" "" 0
run "echo -ne \"message\" | ./kry -v -k password -m 23158796a45a9392951d9a72dffd6a539b14a07832390b937b94a80ddb6dc18e" "" 1
run "echo -ne \"zprava\" | ./kry -e -n 5 -a ==message -m 23158796a45a9392951d9a72dffd6a539b14a07832390b937b94a80ddb6dc18e" \
    "a3b205a7ebb070c26910e1028322e99b35e846d5db399aae295082ddecf3edd3${nl}zprava\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x58==message${nl}" \
    0


hashFail=0
echo "Checking hashing of random strings"
for ((length=0; length<=1024; length++)); do
    random_string=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c $length)
    expected_hash=$(getHashOf "$random_string")
    run "echo -ne \"$random_string\" | ./kry -c" "$expected_hash${nl}" 0 true
    if [ $? -eq 1 ]; then
        hashFail=$((hashFail+1))
    fi
done


signFail=0
verifyFail=0
echo "Checking signing/verification of random strings and keys"
for ((length=0; length<=192; length++)); do
    random_string=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c $length)
    for ((key_length=1; key_length<=64; key_length++)); do
        random_key=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c $key_length)
        expected_hash=$(getHashOf "$random_key$random_string")
        run "echo -ne \"$random_string\" | ./kry -s -k $random_key" "$expected_hash${nl}" 0 true
        if [ $? -eq 1 ]; then
            signFail=$((signFail+1))
        fi
        run "echo -ne \"$random_string\" | ./kry -v -k $random_key -m $expected_hash" "" 0 true
        if [ $? -eq 1 ]; then
            verifyFail=$((verifyFail+1))
        fi
        wrongHash=$(getHashOf "$random_key$random_string" | tr '0-9a-f' 'a-f0-9')
        run "echo -ne \"$random_string\" | ./kry -v -k $random_key -m $wrongHash" "" 1 true
        if [ $? -eq 1 ]; then
            verifyFail=$((verifyFail+1))
        fi
    done
done

if [ $hashFail -eq 0 ]; then
    echo "+ PASS:  All hashes are correct"
else
    echo "- FAIL:  $hashFail hashes were wrong"
fi

if [ $signFail -eq 0 ]; then
    echo "+ PASS:  All signatures are correct"
else
    echo "- FAIL:  $signFail signatures were wrong"
fi

if [ $verifyFail -eq 0 ]; then
    echo "+ PASS:  All verifications are correct"
else
    echo "- FAIL:  $verifyFail verifications were wrong"
fi


