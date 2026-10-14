#!/bin/sh
# Additive global Forgejo post-receive.d hook. Never blocks an accepted push.
# The mounted SSD mailbox contains only source IDs and the original push time.
export LC_ALL=C
project=$(basename "$PWD" .git)
case "$project" in gcoms|dropship|gchat|drone) ;; *) exit 0 ;; esac
mailbox=/var/lib/gitea/android-release/events
[ -d "$mailbox" ] || exit 0
sequence=0
while read -r before after ref; do
    case "$ref" in
        refs/tags/android-release/*)
            [ "$project" = gcoms ] || continue
            ident=${ref#refs/tags/android-release/}
            case "$ident" in *[!0-9a-f]*) continue ;; esac
            [ "${#ident}" = 64 ] || continue
            ;;
        refs/heads/main|refs/heads/agent/*) ;;
        *) continue ;;
    esac
    # Task branches change; the consumer selects exact configured source refs.
    # Ref names are untrusted JSON input, so emit only this ASCII alphabet.
    case "$ref" in *[!A-Za-z0-9_./-]*) continue ;; esac
    case "$after" in *[!0-9a-f]*|0000000000000000000000000000000000000000) continue ;; esac
    [ "${#after}" = 40 ] || continue
    pushed=$(date +%s)
    sequence=$((sequence + 1))
    name="$project-$pushed-$after-$$-$sequence"
    umask 077
    if printf '{"project":"%s","ref":"%s","commit":"%s","pushed_at":%s}\n' \
        "$project" "$ref" "$after" "$pushed" > "$mailbox/$name.new"; then
        mv "$mailbox/$name.new" "$mailbox/$name.json" || :
    fi
done
exit 0
