// Python `fnmatch.fnmatchcase` re-implementation — IR_CONTRACT.md  .

// Used for the `match.tool` glob criterion . NOT JS `minimatch`
// (which is case-insensitive on Windows and expands `**` differently).
// The port ships Python `fnmatch` semantics verbatim, translated via the
// standard `fnmatch.translate` algorithm: glob -> regex, anchored both
// ends.

// Glob translation table (CPython `fnmatch.translate`):
//   `*`      -> `.*`   (zero or more chars)
//   `?`      -> `.`    (exactly one char)
//   `[seq]`  -> `[seq]` (character class; ranges `[a-z]`, negation `[!seq]`)
//   `[!seq]` -> `[^seq]`
//   `\\x`    -> literal `x` (escape)
//   other    -> literal (regex-escaped)

// Case-sensitive (matches `fnmatchcase`, NOT `fnmatch`). The translated
// regex is anchored at both ends (`^...$`) per CPython 3.10+ semantics.

export function fnmatchCase(name: string, glob: string): boolean {
  const re = translateGlob(glob);
  return re.test(name);
}

function translateGlob(glob: string): RegExp {
  let i = 0;
  let pattern = "(?";
  // CPython 3.10+ emits a fullmatch-shaped pattern (uses `(?s:...)`).
  pattern = "(?:";
  while (i < glob.length) {
    const c = glob[i];
    i += 1;
    if (c === "*") {
      pattern += ".*";
    } else if (c === "?") {
      pattern += ".";
    } else if (c === "[") {
      // Character class.
      let j = i;
      if (j < glob.length && glob[j] === "!") {
        pattern += "[^";
        j += 1;
      } else {
        pattern += "[";
      }
      // A leading `]` or `-` is literal.
      if (j < glob.length && glob[j] === "]") {
        pattern += "\\]";
        j += 1;
      }
      while (j < glob.length && glob[j] !== "]") {
        let ch = glob[j];
        j += 1;
        if (ch === "\\") {
          if (j < glob.length) {
            ch = glob[j];
            j += 1;
          }
        }
        // Range?
        if (j < glob.length && glob[j] === "-" && j + 1 < glob.length && glob[j + 1] !== "]") {
          pattern += regexEscapeClass(ch) + "-";
          j += 1;
          const end = glob[j];
          j += 1;
          if (end === "\\") {
            if (j < glob.length) {
              pattern += regexEscapeClass(glob[j]);
              j += 1;
            }
          } else {
            pattern += regexEscapeClass(end);
          }
        } else {
          pattern += regexEscapeClass(ch);
        }
      }
      if (j >= glob.length) {
        // Unterminated `[` — Python treats it as a literal `[`.
        // Reset: this branch is rare; fall back to escaping.
        pattern = pattern.slice(0, -pattern.endsWith("[") ? 1 : 0);
        pattern += "\\[";
        i = j;
        continue;
      }
      pattern += "]";
      i = j + 1;
    } else if (c === "\\") {
      if (i < glob.length) {
        pattern += regexEscapeChar(glob[i]);
        i += 1;
      } else {
        pattern += "\\\\";
      }
    } else {
      pattern += regexEscapeChar(c);
    }
  }
  pattern += ")";
  // Anchor fullmatch-style (CPython 3.10+ emits `(?s:...)\Z`).
  return new RegExp("^(?:" + pattern + ")$", "s");
}

function regexEscapeChar(c: string): string {
  // Escape regex metacharacters outside a character class.
  if (".+^$(){}|".includes(c)) return "\\" + c;
  return c;
}

function regexEscapeClass(c: string): string {
  // Inside a character class only `]`, `\`, `-` need escaping (and `^`
  // at the start, but we handle negation separately).
  if ("]\\-".includes(c)) return "\\" + c;
  return c;
}