---
# Required
status: '{proposed | rejected | accepted | deprecated | … | superseded by [ADR-0005](0005-example.md)}'
date: '{YYYY-MM-DD when the decision was last updated}'
tags:
 - example-one
 - example-two
# Optional
driver: '{list anyone leading the decision and implementation}'
deciders: '{list everyone involved in the decision}'
consulted: '{list everyone whose opinions are sought (typically subject-matter experts); and with whom there is a two-way communication}'
informed: '{list everyone who is kept up-to-date on progress; and with whom there is a one-way communication}'
---
# {short title of solved problem and solution}

## Context and Problem Statement

{Describe the context and problem statement, e.g., in free form using two to three sentences or in the form of an illustrative story.
 You may want to articulate the problem in form of a question and add links to collaboration boards or issue management systems.}

<!-- This is an optional element. Feel free to remove. -->
## Decision Drivers

* {decision driver 1, e.g., a force, facing concern, …}
* {decision driver 2, e.g., a force, facing concern, …}
* … <!-- numbers of drivers can vary -->

## Considered Options

* {title of option 1}
* {title of option 2}
* {title of option 3}
* … <!-- numbers of options can vary -->

## Decision Outcome

Chosen option: "{title of option 1}", because
{justification. e.g., only option, which meets k.o. criterion decision driver | which resolves force {force} | … | comes out best (see below)}.

<!-- This is an optional element. Feel free to remove. -->
### Consequences

* 🟩 **Good**, because {positive consequence, e.g., improvement of one or more desired qualities, …}
* 🟥 **Bad**, because {negative consequence, e.g., compromising one or more desired qualities, …}
* … <!-- numbers of consequences can vary -->

<!-- This is an optional element. Feel free to remove. -->
## Validation

{describe how the implementation of/compliance with the ADR is validated. E.g., by a review or an ArchUnit test}

<!-- This is an optional element. Feel free to remove. -->
## Pros and Cons of the Options

### {title of option 1}

<!-- This is an optional element. Feel free to remove. -->
{example | description | pointer to more information | …}

* 🟩 **Good**, because {argument a}
* 🟩 **Good**, because {argument b}
<!-- use "neutral" if the given argument weights neither for good nor bad -->
* 🟨 **Neutral**, because {argument c}
* 🟥 **Bad**, because {argument d}
* … <!-- numbers of pros and cons can vary -->

### {title of other option}

{example | description | pointer to more information | …}

* 🟩 **Good**, because {argument a}
* 🟩 **Good**, because {argument b}
* 🟨 **Neutral**, because {argument c}
* 🟥 **Bad**, because {argument d}
* …

<!-- This is an optional element. Feel free to remove. -->
## More Information

{You might want to provide additional evidence/confidence for the decision outcome here and/or
 document the team agreement on the decision and/or
 define when this decision when and how the decision should be realized and if/when it should be re-visited and/or
 how the decision is validated.
 Links to other decisions and resources might here appear as well.}