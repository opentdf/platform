
#!/usr/bin/env bash

set -x

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"

cd "$APP_DIR" || exit 1
if ! pip install -r requirements.txt; then
  echo "Failed to install python deps for roundtrip test"
  exit 1
fi

for e in tdf ntdf; do
  rm -rf sample.{out,{n,}tdf,txt}
  echo "hello-world ${e} sample plaintext" >sample.txt
  if ! python3 ./tdf.py encrypt sample.txt "sample.${e}"; then
    echo ERROR encrypt ${e} failure
    exit 1
  fi

  if ! python3 ./tdf.py decrypt "sample.${e}" sample.out; then
    echo ERROR decrypt ${e} failure
    exit 1
  fi
  cat sample.out
  grep "hello-world ${e} sample"<sample.out
  echo INFO Successful ${e} round trip!
done
