#!/usr/bin/env bash
# ==============================================================================
# Git pre-push hook Nyalai
# ==============================================================================
# Source primaire :
#   portfolio_shared/audits/2026-07-17_post_mortem_cice_public_incident.md
#   Action Item AI-9 (section 7)
#
# Codifie la directive D-12 Pre-push security scan de
#   portfolio_shared/AGENT_STYLE_DIRECTIVES.md
#
# Role : bloquer par grep de patterns critiques toute publication accidentelle
# de credentials, PII sensibles (Khalid), IP VPS production, prospects PII,
# provenance Z-library, sources tierces non-Nyalai, em dashes D-1, ou AI
# signature patterns D-3 avant qu'un git push ne les rende irreversibles.
#
# Comportement :
#   - Le hook itere sur chaque ref push et prend la liste des fichiers
#     modifies dans les commits nouveaux (git diff --name-only RANGE).
#   - Pour chaque fichier existant du delta, grep 8 categories de patterns.
#   - Si au moins un match est detecte, exit 1 => git push refuse.
#   - Sinon exit 0 => push autorise.
#
# Bypass (documenter la raison dans le message de commit ou d'annotation) :
#   git push --no-verify
#
# Desactivation temporaire (a eviter, prefere --no-verify ponctuel) :
#   chmod -x .git/hooks/pre-push
#
# Installation manuelle sur un repo (non versionne car .git/ hors track) :
#   cp portfolio_shared/scripts/git-pre-push-nyalai.sh \
#      <REPO>/.git/hooks/pre-push
#   chmod +x <REPO>/.git/hooks/pre-push
#
# Version : v0.3.6 (2026-07-18 morning)
#   Changelog v0.3.5 -> v0.3.6 (verdicts/*_draft*.md allowlist private) :
#     + is_docs_allowlist etend pour aussi inclure verdicts/*_draft*.md.
#       Les working drafts verdicts sont des documents internes privés
#       en cours de rédaction. Ils contiennent legitimement le prénom
#       du soumettant R-02 et peuvent avoir des em dashes ou vocabulaire
#       non-poli avant conversion vers verdict publié final.
#     + Allowlist s'étend à CAT 1 (Khalid), CAT 4 (Prospects), CAT 7
#       (em dashes), CAT 8 (AI signature). CAT 2/3/5/6 restent enforced.
#     + Detection : Sebastien vient de git mv R-02_runstack_draft.md
#       vers R-02_draft.md 2026-07-18 morning, hook v0.3.5 bloquait
#       le nouveau fichier tracked.
#   Changelog v0.3.4 -> v0.3.5 (curriculum/volume_1 allowlist for CAT 4) :
#     + is_docs_allowlist etend pour aussi inclure curriculum/volume_1/*.md
#       et */curriculum/volume_1/*.md. Les chapitres du curriculum Volume 1
#       citent legitimement des collaborateurs academiques publics
#       d'Andrew Lo, Simonian, Harvey, etc. (par exemple Ch25 mentionne
#       Jillian Ross comme PhD student CSAIL, publiquement connue via
#       les talks Lo Griffin GSAS / MIT / Harvard).
#     + Detection : Sebastien tentait de commit Phase 3 curriculum
#       corrections 2026-07-18 morning, hook v0.3.4 bloquait Ch25.
#   Changelog v0.3.3 -> v0.3.4 (audits/*.md allowlist for CAT 4 Prospects) :
#     + is_docs_allowlist etend pour aussi inclure audits/*.md et */audits/*.md.
#       Les audit files documentent legitimement les mentions doctrine et
#       peuvent citer des collaborateurs academiques publics (par exemple
#       Jillian Ross dans une entree Andrew Lo Griffin GSAS). Meta-references
#       a doctrine, pas des expositions prospect PII.
#     + Detection : Sebastien tentait de commit les 4 phase audits 2026-07-17
#       late evening, hook v0.3.3 bloquait phase3a doctrine audit legitimement.
#   Changelog v0.3.2 -> v0.3.3 (doctrine allowlist for CAT 4 Prospects) :
#     + CAT 4 (Prospects PII) : allowlist etendue via is_docs_allowlist
#       pour inclure THE_REFUSAL_DOCTRINE_v*.md. Justification MEASURED :
#       la doctrine cite legitimement Jillian Ross comme PhD student
#       CSAIL avec Andrew Lo (publique via les talks Lo Griffin GSAS,
#       MIT, Harvard). Ces mentions doctrine sont acknowledgments
#       academiques publics, pas des expositions prospect PII.
#     + Detection : audit Phase 3a doctrine v0.3.2.3 corrections en cours
#       2026-07-17 late evening, hook v0.3.2 bloquait le push doctrine
#       legitimement, gap dans l'allowlist.
#   Changelog v0.3.1 -> v0.3.2 (blockquote verbatim preservation) :
#     + strip_backticks() etend pour aussi retirer les lignes markdown
#       blockquote (`> ...`) avant scan CAT 7 (em dashes) et CAT 8 (AI
#       signature D-3). Justification Rule 6.1 Truthful : les verbatim
#       quotes preservees dans blockquotes sont des mots humains, pas
#       de la prose Claude, et ne relevent pas des disciplines D-1/D-3.
#     + Trigger : distillation Hoffstein v0.1 "leverage" preservation
#       dans verbatim Corey Hoffstein (financial noun) conflictait avec
#       CAT 8 detection. Fix structurel : blockquote lines allowlist.
#     + CAT 1-5 (PII/credentials/prospects/Z-library) restent scannees
#       meme dans blockquotes : le hook doit continuer a bloquer
#       exposure accidentelle meme dans une citation.
#   Changelog v0.3 -> v0.3.1 (self-triggering fix) :
#     + Allowlist file `scripts/git-pre-push-nyalai.sh` (le hook lui-meme)
#       pour CAT 1-5 et CAT 8. Le hook est le pattern registry : par
#       construction il contient les regex de detection literals, ce qui
#       cree un self-trigger si scan strict. Exemption necessaire.
#     + Allowlist curriculum/qcm/*.md pour CAT 5 (Z-library) et CAT 8
#       (AI signature). Les QCM citent ces patterns pour reinforcement
#       (Q10 CAT 5 pedagogie, Q28 CAT 8 pedagogie).
#     + CAT 3 credentials continue de scanner tous les fichiers sauf le
#       hook (allowlist explicite via is_hook_script_self) parce qu'un
#       credential dans une QCM ou dans du code livrable est jamais
#       legitime.
#     + Detecte en push simulation Sebastien 2026-07-17 evening apres
#       activation locale hook v0.3.
#   Changelog v0.2 -> v0.3 :
#     + Allowlist curriculum/qcm/*.md pour CAT 1 (Khalid), CAT 2 (VPS),
#       CAT 4 (Prospects). Justification : les QCM sont des instruments
#       pedagogiques dont le role explicite est de citer les patterns
#       interdits pour reinforcement mnemonique. portfolio_shared est
#       PRIVATE (risque exposition null). CAT 3 (credentials), CAT 5
#       (z-library), CAT 6 (sources tierces raw), CAT 7 (em dashes) et
#       CAT 8 (AI signature) restent appliques aux QCM sans exception.
#       Validee Sebastien 2026-07-17 soir suite audit Level 2 STANDARD
#       QCM S2 (472 lignes, 8 mentions khalid + 1 VPS + 3 prospects
#       toutes structurelles pedagogiques).
#   Changelog v0.1 -> v0.2 :
#     + CAT 6 : Sources tierces non-Nyalai (transparency boundary discipline)
#     + CAT 7 : Em dashes D-1 auto-detect dans fichiers livrables
#     + CAT 8 : AI signature patterns D-3 auto-detect
# ==============================================================================

set -u

REMOTE="${1:-}"
URL="${2:-}"

# SHA null utilise par git pour signaler creation ou suppression d'une ref.
Z40="0000000000000000000000000000000000000000"

REJECTED=0
HITS=()

# ------------------------------------------------------------------------------
# Fonction utilitaire : "strip backticks"
# ------------------------------------------------------------------------------
# Retire tout contenu enclos entre backticks simples ainsi que les blocs
# entre triple backticks. Retire aussi les lignes de blockquote markdown
# `> ...` (verbatim quotes preservees pour Rule 6.1 Truthful : les mots
# des humains cites ne sont pas de la prose Claude et ne relevent pas des
# disciplines D-1 em dash / D-3 AI signature). Utilise par CAT 7 et CAT 8
# pour distinguer contenu livrable (prose auteur) du code / references
# entre backticks / verbatim quotes.
#
# Extension v0.3.2 (2026-07-17 evening) : ajout strip blockquote lignes.
# Trigger : distillation Hoffstein v0.1 verbatim "leverage" preservation
# Rule 6.1 conflictait avec CAT 8 detection D-3.
strip_backticks() {
    # Retire d'abord les blocs code triple-backticks (multi-lignes),
    # puis les lignes blockquote `> ...`, puis les inline backticks.
    awk '
        BEGIN { in_fence = 0 }
        /^[[:space:]]*```/ { in_fence = !in_fence; next }
        {
            if (in_fence) next
            # Skip markdown blockquote lines (Rule 6.1 verbatim preservation)
            if (match($0, /^[[:space:]]*>/)) next
            # Retire tous les segments `...` sur la ligne
            gsub(/`[^`]*`/, "")
            print
        }
    ' "$1"
}

# ------------------------------------------------------------------------------
# Allowlist CAT 7 / CAT 8 : fichiers qui documentent les patterns interdits
# ------------------------------------------------------------------------------
# Ces fichiers definissent, citent, ou expliquent les patterns bannis. Les
# scanner produirait des faux positifs systematiques. On les exempte de CAT 7
# (em dash) et CAT 8 (AI signature). Les autres categories (Khalid, VPS,
# credentials, prospects, z-library, sources tierces) restent appliquees.
is_docs_allowlist() {
    case "$(basename "$1")" in
        AGENT_STYLE_DIRECTIVES.md) return 0 ;;
        public_artifacts_voice_english.md) return 0 ;;
        public-artifacts-voice-english.md) return 0 ;;
        la_toile_voice_guide.md) return 0 ;;
        la-toile-voice-guide.md) return 0 ;;
        rule-6-naming-canonical.md) return 0 ;;
        rule_6_naming_canonical.md) return 0 ;;
        THE_REFUSAL_DOCTRINE_v*.md) return 0 ;;
    esac
    # v0.3.6 (2026-07-17 late night) : allowlist audits/*.md pour CAT 4.
    # Les audit files documentent legitimement les mentions doctrine et
    # peuvent citer des collaborateurs academiques publics (par exemple
    # Jillian Ross dans une entree Andrew Lo). Ces mentions sont
    # meta-references a la doctrine, pas des expositions prospect PII.
    case "$1" in
        audits/*.md) return 0 ;;
        */audits/*.md) return 0 ;;
    esac
    # v0.3.6 (2026-07-18 morning) : allowlist curriculum/volume_1/*.md
    # pour CAT 4. Les chapitres curriculum Volume 1 citent legitimement
    # des collaborateurs academiques publics d'Andrew Lo, Simonian, etc.
    # (par exemple Ch25 mentionne Jillian Ross comme PhD student CSAIL
    # publiquement connue via les talks Lo Griffin GSAS / MIT / Harvard).
    # Ces mentions sont enseignement academique cross-referencant la
    # doctrine, pas des expositions prospect PII.
    case "$1" in
        curriculum/volume_1/*.md) return 0 ;;
        */curriculum/volume_1/*.md) return 0 ;;
    esac
    # v0.3.6 (2026-07-18 morning) : allowlist verdicts/*_draft*.md pour
    # CAT 1 (Khalid) + CAT 4 (Prospects) + CAT 7 (em dashes) + CAT 8
    # (AI signature). Les working drafts verdicts sont des documents
    # internes privés en cours de rédaction. Ils contiennent legitimement
    # le prénom du soumettant R-02 (référentiel interne) et peuvent avoir
    # des em dashes ou vocabulaire non-poli avant conversion vers verdict
    # publié final. Les verdicts publiés live sur nyalai.com ne portent
    # pas le suffixe _draft et restent scannés strictement. CAT 2 (VPS),
    # CAT 3 (credentials), CAT 5 (Z-library), CAT 6 (sources tierces)
    # restent enforced sur drafts (aucun contexte légitime).
    case "$1" in
        verdicts/*_draft*.md) return 0 ;;
        */verdicts/*_draft*.md) return 0 ;;
    esac
    return 1
}

# ------------------------------------------------------------------------------
# Allowlist CAT 1 / 2 / 4 / 5 / 8 : curriculum QCM files
# ------------------------------------------------------------------------------
# Les fichiers `curriculum/qcm/*.md` sont des instruments pedagogiques dont
# le role explicite est de citer les patterns interdits (Khalid, VPS IP,
# noms de prospects, Z-library, patterns AI signature) pour que Sebastien
# memorise ce que les disciplines detectent. Bloquer ces fichiers rendrait
# la pedagogie inoperante.
#
# portfolio_shared est PRIVATE (visibility MEASURED verifiee 2026-07-17
# via PORTFOLIO_REPOS_VISIBILITY.md v0.2) : risque d'exposition null.
#
# Ce qui reste APPLIQUE aux QCM sans exception (protection non pedagogique) :
#   - CAT 3 (credentials) : aucun contexte legitime pour un credential
#     literal dans une QCM ; un vrai token ghp_ / github_pat_ / sk- / cle
#     privee PEM ne peut jamais etre pedagogique.
#   - CAT 6 (sources tierces raw) : jamais dans une QCM par nature.
#   - CAT 7 (em dashes D-1) : les QCM sont exigees zero em dash.
#
# Validee Sebastien 2026-07-17 soir apres audit Level 2 STANDARD QCM S2.
is_curriculum_qcm() {
    case "$1" in
        curriculum/qcm/*.md) return 0 ;;
        */curriculum/qcm/*.md) return 0 ;;
    esac
    return 1
}

# ------------------------------------------------------------------------------
# Allowlist ALL CAT 1-5 + CAT 8 : hook script self
# ------------------------------------------------------------------------------
# Le hook lui-meme (`scripts/git-pre-push-nyalai.sh`) est le pattern
# registry : par construction il contient les regex literals detectes.
# Sans exemption, chaque publication du hook echoue sur lui-meme (bug
# revele en v0.3 push simulation Sebastien 2026-07-17 evening).
#
# Portee exemption : CAT 1 (Khalid regex), CAT 2 (VPS regex), CAT 3
# (credentials regex : les patterns type ghp_[a-zA-Z0-9]{36,} sont
# non-matchant contre eux-memes mais le pattern -----BEGIN.*PRIVATE.*KEY
# est self-matching et CAT 5 z-library est self-matching), CAT 4
# (prospects regex), CAT 5 (Z-library regex), CAT 8 (AI signature words
# listes dans la definition CAT 8 : delve, In conclusion, etc).
#
# CAT 6 (sources tierces path detection) reste applique parce que le hook
# ne matche pas les paths type "research/transcripts_*". CAT 7 (em dashes)
# reste applique parce que le hook a 0 em dash MEASURED.
is_hook_script_self() {
    case "$1" in
        scripts/git-pre-push-nyalai.sh) return 0 ;;
        */scripts/git-pre-push-nyalai.sh) return 0 ;;
    esac
    return 1
}

# ------------------------------------------------------------------------------
# stdin contient les lignes "local_ref local_sha remote_ref remote_sha"
# pour chaque ref pushee (peut etre plusieurs si push --all ou multi-branches).
# ------------------------------------------------------------------------------
while read -r local_ref local_sha remote_ref remote_sha; do
    # Ligne vide de fin de stream : ignore.
    if [ -z "${local_sha:-}" ]; then
        continue
    fi

    # Suppression de branche cote remote : rien a scanner.
    if [ "$local_sha" = "$Z40" ]; then
        continue
    fi

    if [ "$remote_sha" = "$Z40" ]; then
        # Nouvelle branche : scanner tous les commits accessibles depuis local_sha
        # qui ne sont pas deja dans une ref remote connue.
        RANGE="$local_sha --not --remotes"
    else
        # Mise a jour d'une branche existante : delta remote..local.
        RANGE="$remote_sha..$local_sha"
    fi

    # Liste des fichiers touches dans le delta.
    # `git diff --name-only` retourne un fichier par ligne, chemins relatifs
    # depuis la racine du repo.
    # shellcheck disable=SC2086
    FILES=$(git diff --name-only $RANGE 2>/dev/null || true)

    if [ -z "$FILES" ]; then
        continue
    fi

    # === CATEGORIE 1 : Khalid PII =============================================
    # Source discipline : memory khalid_bots_not_runstack (2026-07-13)
    # Verbatim : "DO NOT mention Khalid in any Nyalai artifact"
    # Patterns : prenom Khalid + prenom Ahmed (nom de famille documente).
    # Allowlist : curriculum/qcm/*.md (pedagogie) + hook script self +
    # is_docs_allowlist (v0.3.6 : verdicts/*_draft*.md working drafts privés).
    for f in $FILES; do
        if [ ! -f "$f" ]; then continue; fi
        if is_curriculum_qcm "$f"; then continue; fi
        if is_hook_script_self "$f"; then continue; fi
        if is_docs_allowlist "$f"; then continue; fi
        if grep -qiE "\bkhalid\b|\bahmed\b" "$f" 2>/dev/null; then
            HITS+=("CAT 1 Khalid PII : $f")
            REJECTED=1
        fi
    done

    # === CATEGORIE 2 : IP VPS production ======================================
    # Source discipline : memory vps_hetzner_migration
    # Patterns : IP publique VPS Hetzner + hostname documente.
    # Allowlist : curriculum/qcm/*.md (pedagogie) + hook script self.
    for f in $FILES; do
        if [ ! -f "$f" ]; then continue; fi
        if is_curriculum_qcm "$f"; then continue; fi
        if is_hook_script_self "$f"; then continue; fi
        if grep -qE "5\.161\.246\.190|badoun@badoun-trading-01" "$f" 2>/dev/null; then
            HITS+=("CAT 2 IP VPS ou hostname production : $f")
            REJECTED=1
        fi
    done

    # === CATEGORIE 3 : Credentials patterns ===================================
    # Patterns issus des formats standards :
    #   ghp_XXX          : GitHub Personal Access Token classic
    #   github_pat_XXX   : GitHub PAT fine-grained
    #   sk-XXX           : OpenAI / Anthropic key prefix
    #   BEGIN PRIVATE    : bloc PEM cle privee generique
    #   BEGIN RSA        : bloc PEM cle RSA
    #   ssh-ed25519 AAAA : cle publique ed25519 en clair (moins critique mais utile)
    # Allowlist : hook script self (pattern registry contient les regex).
    for f in $FILES; do
        if [ ! -f "$f" ]; then continue; fi
        if is_hook_script_self "$f"; then continue; fi
        if grep -qE "ghp_[a-zA-Z0-9]{36,}|github_pat_[a-zA-Z0-9_]{80,}|sk-[a-zA-Z0-9]{40,}|-----BEGIN.*PRIVATE.*KEY|-----BEGIN.*RSA.*PRIVATE|ssh-ed25519 AAAA[a-zA-Z0-9+/]{40,}" "$f" 2>/dev/null; then
            HITS+=("CAT 3 Credentials pattern : $f")
            REJECTED=1
        fi
    done

    # === CATEGORIE 4 : Prospects PII ==========================================
    # Source discipline : memory network_prospect_intelligence_july11
    # Patterns : noms warm prospects Q4 2026 confidentialite.
    # Allowlist : curriculum/qcm/*.md (pedagogie) + hook script self.
    # Allowlist doctrine : THE_REFUSAL_DOCTRINE_v*.md legitimement cite des
    # collaborateurs academiques publics (par exemple Jillian Ross comme
    # PhD student CSAIL avec Andrew Lo, publique via les talks Lo Griffin
    # GSAS/MIT/Harvard). Ces mentions doctrine sont acknowledgments
    # academiques publics, pas des expositions prospect PII. is_docs_allowlist
    # inclut THE_REFUSAL_DOCTRINE_v*.md par design.
    for f in $FILES; do
        if [ ! -f "$f" ]; then continue; fi
        if is_curriculum_qcm "$f"; then continue; fi
        if is_hook_script_self "$f"; then continue; fi
        if is_docs_allowlist "$f"; then continue; fi
        if grep -qiE "\bbricken\b|jillian ross|\bsallettaz\b|\bbengs\b|\bdurand\b" "$f" 2>/dev/null; then
            HITS+=("CAT 4 Prospects PII (Bricken/Ross/Sallettaz/Bengs/Durand) : $f")
            REJECTED=1
        fi
    done

    # === CATEGORIE 5 : Z-library provenance ===================================
    # Source discipline : audit 2026-07-17 red_team/source_books/ (AI-4)
    # Patterns : signatures filename ou reference domaines Z-library.
    # Allowlist : curriculum/qcm/*.md (Q10 cite CAT 5 pedagogiquement)
    #             + hook script self (contient patterns regex Z-library).
    for f in $FILES; do
        if [ ! -f "$f" ]; then continue; fi
        if is_curriculum_qcm "$f"; then continue; fi
        if is_hook_script_self "$f"; then continue; fi
        if grep -qiE "z-library|1lib\.sk|z-lib\.sk|zlib\.pub" "$f" 2>/dev/null; then
            HITS+=("CAT 5 Z-library provenance : $f")
            REJECTED=1
        fi
    done

    # === CATEGORIE 6 : Sources tierces non-Nyalai =============================
    # Source discipline : memory nyalai_transparency_boundary_discipline (2026-07-17)
    # Verbatim Sebastien : "Les gens n'ont pas a savoir la methode pour avoir
    # les sources tangibles". Transparence sur cadre + resultats, PAS sur
    # modus operandi ni sources tierces raw.
    #
    # Bloque :
    #   - Fichiers .txt .pages .docx .mp3 .mp4 .wav .m4a .epub dans
    #     research/transcripts_*/ , research/transcripts/ , research/audio/ ,
    #     research/videos/ , research/interviews/
    #   - Fichiers dont le nom commence par "Transcript of", "Interview with",
    #     ou "Podcast" (contenus tiers copyright presume).
    #
    # Autorise : nos distillations .md dans les memes dossiers (travail propre).
    for f in $FILES; do
        if [ ! -f "$f" ]; then continue; fi

        # Path-based detection : dossiers de sources tierces raw
        case "$f" in
            research/transcripts_*/*|research/transcripts/*|research/audio/*|research/videos/*|research/interviews/*)
                case "$f" in
                    *.txt|*.pages|*.docx|*.mp3|*.mp4|*.wav|*.m4a|*.epub|*.doc|*.rtf)
                        HITS+=("CAT 6 Source tierce raw (path+ext) : $f")
                        REJECTED=1
                        ;;
                esac
                ;;
        esac

        # Filename pattern detection : "Transcript of", "Interview with", "Podcast"
        base=$(basename "$f")
        case "$base" in
            "Transcript of "*|"Transcript_of_"*|"transcript_of_"*)
                HITS+=("CAT 6 Source tierce (filename 'Transcript of') : $f")
                REJECTED=1
                ;;
            "Interview with "*|"Interview_with_"*|"interview_with_"*)
                HITS+=("CAT 6 Source tierce (filename 'Interview with') : $f")
                REJECTED=1
                ;;
            "Podcast "*|"Podcast_"*)
                # Autorise si extension .md (nos analyses)
                case "$f" in
                    *.md) : ;;
                    *)
                        HITS+=("CAT 6 Source tierce (filename 'Podcast') : $f")
                        REJECTED=1
                        ;;
                esac
                ;;
        esac
    done

    # === CATEGORIE 7 : Em dashes D-1 auto-detect ==============================
    # Source discipline : AGENT_STYLE_DIRECTIVES.md D-1 (universel, 2026-07-14)
    # Regle : zero em dash dans tout artifact Nyalai.
    #
    # Portee : fichiers livrables (prose) uniquement.
    #   - .md .mdx .astro .txt : detecter
    #   - .py .sh .css .js .ts .tsx .jsx .html .json .yml .yaml : ignorer
    #     (em dashes eventuels dans commentaires ou strings referentiels)
    #
    # Detection intelligente : strip backticks (inline + code fences) puis grep.
    # Un em dash (U+2014) cite entre backticks (documentation D-1 elle-meme)
    # est autorise, car strip_backticks retire ces occurrences avant detection.
    #
    # Allowlist : fichiers qui documentent D-1 (voir is_docs_allowlist).
    # Bypass : `git push --no-verify` pour cas structurels legitimes.
    for f in $FILES; do
        if [ ! -f "$f" ]; then continue; fi
        case "$f" in
            *.md|*.mdx|*.astro|*.txt) : ;;
            *) continue ;;
        esac
        if is_docs_allowlist "$f"; then continue; fi

        # Strip backticks puis compter em dashes restants
        em_count=$(strip_backticks "$f" | grep -c $'\xe2\x80\x94' 2>/dev/null || echo 0)
        # Nettoie eventuels retours multiples
        em_count=${em_count//[!0-9]/}
        if [ -n "$em_count" ] && [ "$em_count" -gt 0 ]; then
            HITS+=("CAT 7 Em dash D-1 ($em_count occurrence hors backticks) : $f")
            REJECTED=1
        fi
    done

    # === CATEGORIE 8 : AI signature patterns D-3 ==============================
    # Source discipline : AGENT_STYLE_DIRECTIVES.md D-3 (2026-07-06)
    # Patterns bannis : delve, leverage, unlock, seamlessly, landscape,
    # tapestry, showcase, "In conclusion", "Ultimately", "it's important to
    # note", "at its core", "in essence", "furthermore", "moreover",
    # "not only", "This is not just", "It's worth noting", "moreover".
    #
    # Portee : fichiers livrables .md et .astro uniquement.
    # Detection : strip backticks puis grep -iE case-insensitive avec word
    # boundaries. Les patterns cites entre backticks (documentation D-3) sont
    # exemptes automatiquement.
    #
    # Allowlist : fichiers qui documentent D-3 (voir is_docs_allowlist).
    # Allowlist additionnelle : curriculum/qcm/*.md (Q28 cite AI signature
    # patterns delve/leverage/etc pedagogiquement) + hook script self.
    # Bypass : `git push --no-verify`.
    for f in $FILES; do
        if [ ! -f "$f" ]; then continue; fi
        case "$f" in
            *.md|*.mdx|*.astro) : ;;
            *) continue ;;
        esac
        if is_docs_allowlist "$f"; then continue; fi
        if is_curriculum_qcm "$f"; then continue; fi
        if is_hook_script_self "$f"; then continue; fi

        stripped=$(strip_backticks "$f")

        # Patterns simples (mots isoles, word boundary)
        pattern_words="\\b(delve|delving|delved|delves|unlock|unlocking|unlocked|unlocks|seamlessly|seamless|tapestry|showcase|showcasing|showcased|showcases)\\b"
        # Phrases (case-insensitive) : detectees sans word boundary strict
        pattern_phrases="it's important to note|at its core|in essence|not only[[:space:]]+[a-z]+[[:space:]]+but[[:space:]]+also|furthermore|moreover|In conclusion|Ultimately,|This is not just|It's worth noting"

        hits_found=()

        # Word patterns
        if echo "$stripped" | grep -qiE "$pattern_words" 2>/dev/null; then
            matched=$(echo "$stripped" | grep -oiE "$pattern_words" | sort -u | head -3 | tr '\n' ',' | sed 's/,$//')
            hits_found+=("$matched")
        fi

        # Phrase patterns
        if echo "$stripped" | grep -qiE "$pattern_phrases" 2>/dev/null; then
            matched=$(echo "$stripped" | grep -oiE "$pattern_phrases" | sort -u | head -3 | tr '\n' ',' | sed 's/,$//')
            hits_found+=("$matched")
        fi

        # "leverage" en verbe : detecte tout "leverage" et laisse humain juger
        if echo "$stripped" | grep -qiE "\\bleverag(e|es|ed|ing)\\b" 2>/dev/null; then
            hits_found+=("leverage")
        fi

        # "landscape" : mot commun mais liste D-3 etendue. Detecte, humain juge.
        if echo "$stripped" | grep -qiE "\\blandscape[s]?\\b" 2>/dev/null; then
            hits_found+=("landscape")
        fi

        if [ "${#hits_found[@]}" -gt 0 ]; then
            joined=$(IFS='|'; echo "${hits_found[*]}")
            HITS+=("CAT 8 AI signature D-3 ($joined) : $f")
            REJECTED=1
        fi
    done

done

if [ "$REJECTED" -eq 1 ]; then
    echo ""
    echo "=========================================="
    echo "PRE-PUSH HOOK NYALAI v0.3.6 : PUSH REFUSE"
    echo "=========================================="
    echo ""
    echo "Le hook pre-push a detecte des patterns critiques dans les fichiers"
    echo "en cours d'etre pushes :"
    echo ""
    for hit in "${HITS[@]}"; do
        echo "  - $hit"
    done
    echo ""
    echo "Discipline propagation_aware_audit : doute = investiguer, pas escalade."
    echo ""
    echo "Resolution :"
    echo "  a. Corriger les fichiers pour retirer les patterns detectes,"
    echo "     amender le commit (git commit --amend / git rebase -i),"
    echo "     puis relancer git push."
    echo "  b. Pour CAT 1-5 (PII, credentials, sources tierces) :"
    echo "     sanitize avant de pousser, jamais --no-verify."
    echo "  c. Pour CAT 7 (em dashes) : remplacer par : ou . ou ( )"
    echo "     (heuristique D-1 dans AGENT_STYLE_DIRECTIVES.md)."
    echo "  d. Pour CAT 8 (AI signature) : reformuler prose en langue directe"
    echo "     (D-3 dans AGENT_STYLE_DIRECTIVES.md)."
    echo "  e. Bypass explicite si faux positif structurel legitime :"
    echo "     git push --no-verify"
    echo "     (documenter la raison dans le message de commit)"
    echo ""
    echo "Post-mortem incident cice 2026-07-17 : ce hook code AI-9."
    echo "=========================================="
    exit 1
fi

echo "PRE-PUSH HOOK NYALAI v0.3.6 : 0 pattern critique detecte. Push autorise."
exit 0
