# AI Agent Rules

## 1. Core Principle
Before writing or modifying code, understand the existing codebase first.
The existing architecture, conventions, patterns, and implementation style are the source of truth.
Do not introduce a new pattern when an existing project pattern can be reused.
When a requested change conflicts with an existing convention, flag the conflict and ask rather than silently picking one side.

---

## 2. Before Writing Code
Always:
1. Inspect the relevant files and surrounding implementation.
2. Understand how the existing feature works, including edge cases already handled.
3. Identify existing utilities, services, components, middleware, and patterns that can be reused.
4. Check related database models, APIs, and frontend/backend flows.
5. Identify dependencies and possible side effects — what else imports or calls this code.
6. Check for existing tests covering the area, and read them before changing behavior they assert on.
7. Form a clear implementation plan before making changes.

Do not start coding based only on assumptions. If a file, API, or behavior can't be verified by inspection, say so explicitly instead of guessing.

---

## 3. Codebase Consistency
All new code must feel like it belongs to the existing codebase.
Follow existing:
- Folder structure
- Naming conventions
- Type conventions
- API patterns
- Database patterns
- Error handling
- Validation
- Logging
- Testing patterns
- Component patterns
- State management patterns

Do not introduce unnecessary frameworks, libraries, abstractions, or architectural patterns.
If two conflicting patterns already exist in the codebase, match whichever the immediate surrounding code uses rather than inventing a third.

---

## 4. Simplicity — Do Not Over-Engineer
Prefer:
Simple > clever
Explicit > overly abstract
Reusable > duplicated
Maintainable > optimized prematurely

**Match the size of the solution to the size of the problem.** If a task can be solved in 2 lines, write 2 lines — not a 50-line abstraction with configs, helper classes, or "future-proofing" no one asked for.
Do not add layers, wrappers, design patterns, or generalized utilities for a single, simple use case.
Only introduce an abstraction when there is a clear reason for it — a real second use case, not a hypothetical future one.
Before writing a solution, ask: what's the smallest change that correctly and durably solves exactly what was requested? Write that.

---

## 5. Security
Security is a default requirement.
Never:
- Expose secrets or credentials, including in logs, error messages, commit history, or example/config files.
- Log passwords, tokens, MFA secrets, API keys, session identifiers, or other sensitive data.
- Disable security controls to make implementation easier.
- Trust client-side authorization; always re-check on the server/backend.
- Bypass existing authentication or authorization, even temporarily "for testing."
- Introduce insecure cryptographic implementations.
- Store sensitive authentication data insecurely.
- Introduce injection risks (SQL, command, template, XSS) — always use parameterized queries and existing sanitization utilities.

Use established security libraries and existing project security patterns whenever possible.
If a task seems to require weakening a security control, stop and flag it instead of proceeding.

---

## 6. Changes
Keep changes focused on the requested task.
Do not modify unrelated code, reformat untouched files, or fix unrelated bugs in the same change — note them separately instead.
Do not perform large refactors unless they are required for the requested feature.
Prefer small, understandable changes over large rewrites.
Prefer existing dependencies already used in the project over adding new ones; don't add a dependency for something a few lines of code already handles.

---

## 7. Database Changes
Before changing the database:
- Inspect the existing schema.
- Follow existing naming and relationship conventions.
- Consider migrations and existing data.
- Avoid unnecessary schema changes.
- Keep database logic consistent with the existing architecture.

Never make destructive database changes without a clear requirement.

---

## 8. Error Handling
Follow the existing error-handling strategy.
Errors should:
- Be predictable.
- Avoid leaking sensitive information.
- Be handled at the appropriate layer.
- Follow existing API response conventions.

Do not silently ignore errors.

---

## 9. Testing
After implementing a change:
1. Run relevant tests.
2. Run type checking.
3. Run linting.
4. Run relevant security/static analysis.
5. Review the final diff.
6. Fix issues before considering the task complete.

Do not assume code works without verification. If a check can't be run in the current environment, say so explicitly rather than assuming it passed.

---

## 10. AI Agent Behavior
Before modifying code:
> Understand → Plan → Implement → Verify → Review

When uncertain, inspect the repository before making assumptions.
Reuse existing code whenever appropriate.
Do not create duplicate implementations of functionality that already exists.
Do not change architecture simply because another approach looks better.
If a request is ambiguous or could be implemented multiple reasonable ways, state the interpretation being used before proceeding.

---

## 11. Final Review
Before finishing a task, verify:
- The requested functionality works.
- Existing functionality still works.
- No unnecessary files were changed.
- No unnecessary dependencies were added.
- No security controls were weakened.
- Code follows existing conventions.
- Tests and checks pass.
- The implementation is understandable to another developer.
- **The solution isn't bigger than the problem it solves.**

The final implementation should be:
**Secure. Reliable. Consistent. Simple. Maintainable.**