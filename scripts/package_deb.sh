
set -e

RESULT=$(pwd)/result
TEMP=$(mktemp -d)
DIRNAME=$(basename $(pwd))

BASEDIR=$TEMP/$DIRNAME

mkdir -p $BASEDIR
cp -r * $BASEDIR

(
	cd $BASEDIR

	VERSION=$(dpkg-parsechangelog --show-field Version | cut -d '-' -f 1)
	PACKAGE=$(dpkg-parsechangelog --show-field Source)

	debmake -yt
	cd ../$PACKAGE-$VERSION

	sudo pdebuild --buildresult $RESULT -- --use-network yes
)

rm -rf $TEMP
