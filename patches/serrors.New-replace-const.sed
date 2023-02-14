#!/usr/bin/sed -f

# Replace usage of serrors.New and errors.New in package global variables with
# a constant of serrors.StrError.
# Unfortunately, gopatch is not able to do this as it cannot handle declaration groups (gopatch#3).
#
# Use *carefully* with:
#    git ls-files '*.go' | xargs sed -i -f patches/serrors.New-replace-const.sed
#
# Needs some manual fixing in complex cases.

# change s?errors.New to serrors.StrError in variable blocks
#  - accumulate the entire content of the variable block in the hold space
#  - at the end of the variable block, replace all s?errors.New and change the block to a const block if matches where found.
#  - this assumes that a matching variable block _exclusively_ contain s?errors.New error definitions.
/^var (/,/^)/ {
    /^var (/ {h;d}
    /^)/ {
        H
        x
        s/= s\?errors.New(\("[^"]*"\))/serrors.StrError = \1/g
        T # only change this to a const section if this contained a s?errors.New
        s/^var/const/
        b
    }
    # else...
    H;d
}

# handle simple one-line variable declarations
/^var \(\w\+\) = s\?errors.New(\("[^"]*"\))/{
    s//const \1 serrors.StrError = \2/
}
