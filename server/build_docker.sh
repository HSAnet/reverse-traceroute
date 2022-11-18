docker build -t augsburg_traceroute_builder .
docker run -it --rm -v $(pwd):/home/build/bin augsburg_traceroute_builder \
    make -j -C src OUTDIR=/home/build/bin CC=clang-14
