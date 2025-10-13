.RECIPEPREFIX := >
first:
>SOME_URL=http://example.com \
>	echo first

.RECIPEPREFIX := @
second:
@BUILD_TIME=2025-10-13T12:34:56Z \
@	echo second

