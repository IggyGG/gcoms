#!/bin/sh
# Additive cloud Forgejo post-receive hook. This process holds no S3 credentials.
project=$(basename "$PWD" .git)
case "$project" in gcoms|dropship|gchat|drone) ;; *) exit 0 ;; esac
[ "$PWD" = "/data/git/gitea-repositories/ghost-local/$project.git" ] || exit 0
outbox=/data/android-release/outbox
[ -d "$outbox" ] || { printf '%s\n' 'Android push outbox unavailable.' >&2; exit 1; }
umask 077
while read -r before after ref; do
    case "$ref" in
        refs/tags/android-release/*)
            [ "$project" = gcoms ] || continue
            ident=${ref#refs/tags/android-release/}
            case "$ident" in *[!0-9a-f]*) continue ;; esac
            [ "${#ident}" = 64 ] || continue ;;
        refs/heads/main|refs/heads/agent/*) ;;
        *) continue ;;
    esac
    case "$ref" in *[!A-Za-z0-9_./-]*|*..*) continue ;; esac
    [ "${#ref}" -le 256 ] || continue
    case "$after" in *[!0-9a-f]*|0000000000000000000000000000000000000000) continue ;; esac
    [ "${#after}" = 40 ] || continue
    pushed=$(date +%s)
    nonce=$(cat /proc/sys/kernel/random/uuid) || exit 1
    temporary="$outbox/$nonce.new"
    printf '{"schema":1,"project":"%s","repository":"ghost-local/%s","ref":"%s","commit":"%s","pushed_at":%s,"nonce":"%s"}\n' \
        "$project" "$project" "$ref" "$after" "$pushed" "$nonce" > "$temporary" || exit 1
    sync -f "$temporary" || exit 1
    identity=$(sha256sum "$temporary")
    identity=${identity%% *}
    mv "$temporary" "$outbox/$identity.json" || exit 1
    sync -f "$outbox" || exit 1
done
