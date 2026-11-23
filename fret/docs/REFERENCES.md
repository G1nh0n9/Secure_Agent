# References

Comments and docstrings of the modules written under the code rules cite their sources by key, for example `[Saltzer1975]` or `[RFC8259, Sec. 9]`. Every key is defined here; `python -m secure_agent_attach style` fails on a key that is not. Entries follow an IEEE-like style.

## Security design

**[Anderson1972]** J. P. Anderson, *Computer Security Technology Planning Study*, Vols. I and II, Report ESD-TR-73-51, Air Force Electronic Systems Division, Hanscom AFB, MA, USA, Oct. 1972 (NTIS AD-758 206 and AD-772 806). Used for: the reference monitor, a small mechanism that mediates every access and can be verified. The guards keep the original gate the only path to a tool for this reason.

**[Saltzer1975]** J. H. Saltzer and M. D. Schroeder, "The protection of information in computer systems," *Proceedings of the IEEE*, vol. 63, no. 9, pp. 1278-1308, Sept. 1975, doi:10.1109/PROC.1975.9939. Author-hosted copy: https://web.mit.edu/saltzer/www/publications/protection/. Used for the design principles *complete mediation*, *fail-safe defaults*, *least privilege* and *compromise recording*.

**[Schneider2000]** F. B. Schneider, "Enforceable security policies," *ACM Transactions on Information and System Security*, vol. 3, no. 1, pp. 30-50, Feb. 2000, doi:10.1145/353323.353382. Used for: the policies an execution monitor can enforce are safety properties. Every requirement of the catalog is an "always" (safety) requirement.

**[Ligatti2005]** J. Ligatti, L. Bauer, and D. Walker, "Edit automata: enforcement mechanisms for run-time security policies," *International Journal of Information Security*, vol. 4, no. 1-2, pp. 2-16, 2005, doi:10.1007/s10207-004-0046-8. Used for: a monitor may suppress an action and insert another, which is what the guards do when they refuse a call and put a message in its place.

**[Brewer1989]** D. F. C. Brewer and M. J. Nash, "The Chinese Wall security policy," in *Proc. 1989 IEEE Symposium on Security and Privacy*, Oakland, CA, USA, May 1-3, 1989, pp. 206-214. Used for: access that depends on what a subject has already done. The order rules (a tool is forbidden after another one has run; a call cap per turn) are of this kind.

## Standards and guidance

**[RFC8259]** T. Bray, Ed., "The JavaScript Object Notation (JSON) Data Interchange Format," RFC 8259, IETF, Dec. 2017, https://www.rfc-editor.org/info/rfc8259. Section 9 (Parsers) permits an implementation to limit the size of the texts it accepts, the depth of nesting, the range and precision of numbers and the length and contents of strings. Used for the size and depth limits of tool arguments.

**[JSONSchema2020-12]** *JSON Schema: A Media Type for Describing JSON Documents* and *JSON Schema Validation: A Vocabulary for Structural Validation of JSON*, specification draft 2020-12, https://json-schema.org/draft/2020-12/json-schema-core and https://json-schema.org/draft/2020-12/json-schema-validation. Used for the meaning of the keywords the shape check enforces (`type`, `required`, `properties`, `additionalProperties`, `enum`, `maxLength`, `minimum`, `maximum`, `items`). Other keywords are ignored, as the specification allows.

**[OWASP-LLM2025]** OWASP GenAI Security Project, *OWASP Top 10 for LLM Applications 2025*. LLM06:2025 Excessive Agency, https://genai.owasp.org/llmrisk/llm062025-excessive-agency/ ; LLM10:2025 Unbounded Consumption, https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/. Used as the named risks behind the order and content rules (excessive agency) and the budget (unbounded consumption).

**[NIST800-53r5]** Joint Task Force, *Security and Privacy Controls for Information Systems and Organizations*, NIST Special Publication 800-53, Rev. 5, Sept. 2020, doi:10.6028/NIST.SP.800-53r5. Cited control: AC-6 Least Privilege.

**[CC2022-2]** *Common Criteria for Information Technology Security Evaluation*, CC:2022, Part 2: Security functional components (ISO/IEC 15408-2:2022). Components cited, with the names of the CC:2022 XML of the CC2XML project: FAU_GEN.1 Audit data generation; FRU_RSA.1 Maximum quotas; FPT_FLS.1 Failure with preservation of secure state; FDP_ACF.1 Security attribute-based access control; FDP_IFF.1 Simple security attributes.

**[Pnueli1989]** A. Pnueli and R. Rosner, "On the synthesis of a reactive module," in *Proc. 16th ACM SIGPLAN-SIGACT Symposium on Principles of Programming Languages (POPL '89)*, 1989, pp. 179-190, doi:10.1145/75277.75293. Used for: realizability, the question whether an implementation exists that satisfies a specification against every behaviour of the environment.

## Testing

**[Miller1990]** B. P. Miller, L. Fredriksen, and B. So, "An empirical study of the reliability of UNIX utilities," *Communications of the ACM*, vol. 33, no. 12, pp. 32-44, Dec. 1990. Author-hosted copy: https://ftp1.cs.wisc.edu/par-distr-sys/papers/fuzz.pdf. Used for: random input as a way to find faults (fuzz testing).

**[Claessen2000]** K. Claessen and J. Hughes, "QuickCheck: a lightweight tool for random testing of Haskell programs," in *Proc. Fifth ACM SIGPLAN International Conference on Functional Programming (ICFP '00)*, 2000, pp. 268-279. Copy: https://www.cis.upenn.edu/~bcpierce/courses/552-2008/resources/icfp-quickcheck.pdf. Used for: properties stated once and tested on generated inputs.

## Code style

**[PEP8]** G. van Rossum, B. Warsaw, and A. Coghlan, "PEP 8 - Style Guide for Python Code," Python Enhancement Proposals, https://peps.python.org/pep-0008/. Lines of at most 79 characters, comments and docstrings of at most 72.

**[PEP257]** D. Goodger and G. van Rossum, "PEP 257 - Docstring Conventions," Python Enhancement Proposals, https://peps.python.org/pep-0257/. One-line summary in the imperative, ending in a period, blank line before the rest.

**[PEP484]** G. van Rossum, J. Lehtosalo, and L. Langa, "PEP 484 - Type Hints," Python Enhancement Proposals, https://peps.python.org/pep-0484/.

**[GoogleStyle]** *Google Python Style Guide*, Google, https://google.github.io/styleguide/pyguide.html. Section headings of docstrings: Args, Returns, Raises, Attributes.
