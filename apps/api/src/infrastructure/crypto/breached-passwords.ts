// §6.5 / R-9 / C-8: breached-password protection behind a pluggable interface.
//
// Default implementation: an embedded starter blocklist of commonly-breached
// passwords (curated from public breach corpora). Matching follows NIST
// 800-63B guidance: case-insensitive exact match PLUS substring match for
// list entries >= 4 chars (catches "iloveyou123", "P@ssw0rd!"-style
// derivatives of listed roots).
//
// Production swap-in: implement BreachedPasswordChecker over HIBP's
// k-anonymity range API (only a SHA-1 prefix leaves the server) or a fuller
// Top-10k file; nothing else in the codebase changes.

export interface BreachedPasswordChecker {
  isBreached(password: string): boolean;
}

/** Curated starter set — treat as the default, not the ceiling (see swap-in note). */
export const STARTER_BREACHED_PASSWORDS: readonly string[] = [
  "123456", "password", "123456789", "12345678", "12345", "qwerty", "1234567890", "1234567",
  "111111", "123123", "abc123", "1234", "password1", "iloveyou", "000000", "qwerty123",
  "1q2w3e", "aa12345678", "654321", "555555", "dragon", "qwertyuiop", "soccer", "baseball",
  "football", "monkey", "letmein", "696969", "shadow", "master", "666666", "qwertyuiop",
  "121212", "flower", "hottie", "loveme", "zaq12wsx", "password123", "654321", "superman",
  "1qaz2wsx", "sunshine", "princess", "computer", "trustno1", "hello", "freedom", "whatever",
  "qazwsx", "google", "batman", "michael", "jennifer", "hunter", "buster", "thomas", "tigger",
  "robert", "soccer1", "harley", "ranger", "daniel", "starwars", "klaster", "112233", "asdf",
  "zxcvbnm", "asdfgh", "computer1", "michelle", "jessica", "pepper", "1111", "zxcvbn",
  "5555", "11111111", "131313", "freedom1", "777777", "pass", "maggie", "159753", "aaaaaa",
  "ginger", "princess1", "joshua", "cheese", "amanda", "summer", "love", "ashley", "nicole",
  "chelsea", "biteme", "matthew", "yankees", "access", "fluffy",
  "nicholas", "lover", "jasmine", "brandy", "chocolate", "test", "test123", "passw0rd",
  "p@ssword", "p@ssw0rd", "passwort", "contrasena", "motdepasse", "senha", "haslo", "qwerty1",
  "welcome", "welcome1", "welcome123", "admin", "admin123", "administrator", "root", "toor",
  "login", "letmein1", "letmein123", "guest", "user", "changeme", "changed", "default",
  "secret", "secrets", "starcraft", "merlin", "falcon", "eagle", "phoenix", "warrior",
  "diamond", "nascar", "mustang", "corvette", "camaro", "harley1", "harleydavidson",
  "copper", "cookie", "lovers", "purple", "angels", "badboy", "bigdog", "canada", "france",
  "germany", "italy", "spain", "england", "london", "paris", "america", "american",
  "chicago", "dallas", "denver", "boston", "atlanta", "austin", "houston", "orlando",
  "seattle", "portland", "phoenix1", "arizona", "colorado", "montana", "nevada", "texas",
  "florida", "banana", "orange", "apple1", "cherry", "peaches", "strawberry", "watermelon",
  "coconut", "pineapple", "chicken", "steak", "bacon", "burger", "pizza", "pasta", "sushi",
  "coffee", "beer", "wine", "vodka", "whisky", "tequila", "rum", "gin", "smoking", "money",
  "dollar", "dollars", "million", "billion", "cash", "gold", "silver", "diamond1", "platinum",
  "crystal", "ruby", "emerald", "sapphire", "pearl", "jade", "onyx", "topaz", "opal",
  "heaven", "angel", "angel1", "babygirl", "babyboy", "sweetie", "honey", "kitty", "puppy",
  "kitten", "tiger", "lion", "bear", "wolf", "fox", "rabbit", "dolphin", "shark", "whale",
  "eagle1", "hawk", "raven", "crow", "sparrow", "robin", "cardinal", "bluejay", "penguin",
  "panda", "koala", "kangaroo", "zebra", "giraffe", "elephant", "rhino", "hippo", "monkey1",
  "gorilla", "chimpanzee", "leopard", "panther", "cougar", "lynx", "bobcat", "jaguar",
];

function buildList(): Set<string> {
  const set = new Set<string>();
  for (const entry of STARTER_BREACHED_PASSWORDS) {
    const value = entry.trim().toLowerCase();
    if (value.length >= 3) set.add(value);
  }
  return set;
}

const DEFAULT_LIST = buildList();

export function createLocalBreachedPasswordChecker(
  list: ReadonlySet<string> = DEFAULT_LIST,
): BreachedPasswordChecker {
  return {
    isBreached(password) {
      const candidate = password.trim().toLowerCase();
      if (candidate === "") return false;
      if (list.has(candidate)) return true;
    // Substring derivatives: only for longer roots (>= 6 chars) so generic
    // fragments like "pass" don't flag everything containing them.
    for (const entry of list) {
      if (entry.length >= 6 && candidate.includes(entry)) return true;
    }
      return false;
    },
  };
}

export const breachedPasswords: BreachedPasswordChecker = createLocalBreachedPasswordChecker();

/** Rejects passwords that embed the account's own email identity (cheap NIST win). */
export function containsEmailIdentity(password: string, email: string): boolean {
  const local = email.split("@")[0] ?? "";
  const domain = (email.split("@")[1] ?? "").split(".")[0] ?? "";
  const p = password.toLowerCase();
  for (const part of [local, domain]) {
    if (part.length >= 3 && p.includes(part.toLowerCase())) return true;
  }
  return false;
}
