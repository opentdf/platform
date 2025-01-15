# Error condition best practices

## Advice about exposing errors in our APIs

When updating code in this repository,
consider the following best practices for exposing errors in our APIs.
Depending on your contribution, you may alter code that might produce:

- go error types and constants, suitable for use with [`errors.Is` and `errors.As`](https://pkg.go.dev/errors)
- errors exposed over RPC (e.g. with [protocol buffers](https://grpc.io/docs/guides/error/))
- translation of those proto errors into JSON and [HTTP status codes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status) via REST endpoints
- log messages [suitable for ops and SRE](https://www.honeycomb.io/blog/engineers-checklist-logging-best-practices), when contributing to service code
- command line [status codes](https://tldp.org/LDP/abs/html/exitcodes.html)

This document focuses on the first category, go `error` typed return values.

### Concerns for Golang Library Developers

- When a library does not provide explicitly exported and documented error types and constants,
  application developers might depend on `strings.Contains()`
  which bind their applications to the error message and prohibit improving error language
  - Prefer using sentinel values for expected conditions
    Sentinels should be named `Err?{Noun}{Case}`, where:
      *Noun* is a word that describes the group of error conditions or scenario
      and *Case* is an adjective or short description of the error type. The Err
      prefix indicates an unexpected condition;
      for expected conditions it should be left off
  - Prefer to use custom types for 'unexpected' error conditions.
    These allow for additional detail and assisting with debugging
    and can provide additional context for handling in application code
- Exporting too much or too many types
  will require us to support the variable or deprecate it
  - Wrap with an non-exported type or `fmt.Errorf` to provide additional context to ops
    without exposing more handling capabilities to the application
- Returned errors may be explicity ignored with an `_`.
- Errors in `defer` blocks should either be returned or wrapped and returned using named return types
  OR logged in place

#### Semantic Versioning with Errors in Go

- Once a type or constant is exported in a tagged release,
  removing it is a backwards-incompatible change
- Increasing the set of expected type of errors that will be returned at an exported site
  should, generally, count as a minor version (feature enhancement)
- Reducing the types or tightening the types returned
  will often be a patch release

## Errors as Developer Experience (DX)

When errors are exposed to developers
they become a form of developer experience by extension.
The priority of the DX will shift depending on the scope of the developers,
e.g. internal or external,
packaged applications or services, etc.

When external developers are using our SDKs
the errors represent the quality of the product.
To better understand this we should consider
the mindset of the developer when they encounter an error.

- The developer is exploring our product
  - In this situation the developer is likely using some kind of documentation or tutorial.
    If they encounter an unexpected error during a guided process
    they will have an immediate negative reaction to our platform and judge its maturity harshly.
  - Alternative situations exist where the developer is using trial an error
    and possibly looking at samples to get it working for their usecase.
    In this situation they will likely be more accepting of errors,
    but hopeful the errors will ease their burden and reveal how to resolve the issue.
  - In both these cases
    developers have not built the kind of rapport with the platform where they are likely to contribute fixes or dig deep
    unless they are instructed to by their employer.
    Failed exploration might lead to investigation into alternative products
- The developer is implementing our product
- The developer is productionizing our product
- The developer is contributing to our product

### Principles

In all these cases some truth remain, errors should be **available**, **useful**, and **actionable**.

#### *available* errors need to be available to developers

The worst situation for external developers is when errors are unavailable.
The immediate reaction is that the application is severely broken.
Consider a situation where an application takes user input
and attempts to write it to a database.
If no error is provided and the data is not revealed in a result
then the user might think the data is lost.
This kind of thinking can result in the failed adoption of the product.

Making errors available is the simplest solution by means of passing errors up,
but I would go one step further and make sure that the error passed up is scoped to the product at hand
and not just a byproduct of the stdlib.
In this way errors are available and easy to identify when stacktraces are unavailable.

> All returned errors must be exported, either as a type or constant.

#### *useful* - errors need to be readable for the target developer language

OpenTDF is targeting English speaking developers,
but with the desire that it is useful internationally.
It isn’t realistic to think that we could support internationalization today with regards to errors,
but if there are ways we can set ourselves up to enrich our errors or expose them some documentation glossary where internationalization is more easily supported.

A good illustration of this is when English speakers use libraries like Ant Design (Alibaba backed frontend design system).
The value of Ant Design as a product excuses some of the grammar and language barriers for native English speakers,
but anecdotally, it seems that English-as-a-second-language (ESL) speakers (who also don’t know Chinese) tend to favor English-driven tooling.

Errors should use proper grammar and spelling.
Usefulness and accuracy of errors is reenforced by the quality of the grammar and spelling of errors.
This is especially true when we are striving for international usage while not having the capacity for internationalization.

Errors should be idiomatic with the language.
This is useful to build rapport and reduce cognitive load.
If the engineers engaged with our product are experienced with the language
then they will adapt to our SDKs with ease.

It is important to note that while we are specialists in data privacy which touches on cryptography
our customers might not be.
Additionally, one value add our products offer is the ability not to specialize,
but rather pay us to be the specialist
while they get to focus on being a specialist in their space.
As such, its important that our errors are scoped to the naive
and instead expose more generic language errors.

Exceptions exist when certain APIs or config are used.
For instance if the developer is choosing a different elliptic curve (EC) type that we don’t support
it would make sense to say “Unsupported curve, use SECP11R2”.
This exception exists because the user is tweaking the curve.

Expect that people have not read the documentation and don’t know the spec.

> Applications can use the `errors.Is` and `As` methods to trigger appropriate behavior in response to an error condition.

#### *actionable* - errors should be actionable to enable the developer to fix their own problem

People like feedback when it's actionable and direct,
otherwise they look for alternatives.

Actionable errors handling can take a variety of forms.

ngrok takes the approach of indexing every error code
and making sure developers can use a search engine to find the error.
In addition their team will monitor the search traffic to errors
and then use that to prioritize specialized documentation pages (e.g. [`ERR_NGROK_120`](https://ngrok.com/docs/errors/err_ngrok_120/) with actionable steps).

[ngrok error philosophy](https://ngrok.com/docs/errors/#philosophy)
[ngrok error standard](https://ngrok.com/docs/api/#errors)

Consistency is part of ensuring errors are actionable.
When error messages look, feel, and read the same way
it reduces the burden on the developer to parse the content
and frees their cognitively to take action on the error.

Actionable errors reduce the burden on our support team
because they are useful tools to get back on track (self-documenting).

> Error types that work with `As` expose sufficient information to be actionable.

This is validated in unit tests that exercise all appropriate conditions.
Similarly, any wrapped types should be exercised in unit tests.

## References

- <https://pkg.go.dev/errors>
- <https://ngrok.com/docs/errors/reference/>
- <https://go.dev/doc/modules/version-numbers#major-version>
- <https://www.honeycomb.io/blog/engineers-checklist-logging-best-practices>
