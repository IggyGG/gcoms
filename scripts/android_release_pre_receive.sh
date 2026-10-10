#!/bin/sh
# Additive Forgejo guard; only this lane's promotion tags are immutable.
[ "$(basename "$PWD" .git)" = gcoms ] || exit 0
while read -r before after ref; do
    case "$ref" in
        refs/tags/android-release/*)
            ident=${ref#refs/tags/android-release/}
            case "$ident" in *[!0-9a-f]*) exit 1 ;; esac
            [ "${#ident}" = 64 ] || exit 1
            [ "$before" = 0000000000000000000000000000000000000000 ] || {
                printf '%s\n' 'Android promotion tags cannot be rewritten or deleted.' >&2
                exit 1
            }
            case "$after" in *[!0-9a-f]*|0000000000000000000000000000000000000000) exit 1 ;; esac
            [ "${#after}" = 40 ] || exit 1
            [ "$(git cat-file -t "$after")" = commit ] || exit 1
            ;;
    esac
done
exit 0
