### Changes

#### Cached selectors approach

Utilize a trigger to set and maintain cached selectors in a dedicated column on the
Subject Condition Set table, then do an overlap `&&` check against the cache instead
of parsing JSON in the `matchSubjectMappings` query.

#### Indices

Index on any relations in the `matchSubjectMappings` query for fastest reads.