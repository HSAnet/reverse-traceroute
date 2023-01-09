config=$(mktemp)
client_env=$(mktemp -d)
workdir=$(mktemp -d)

cd "$workdir"

python3.10 -m venv "$client_env"
"$client_env"/bin/pip3 install /reverse-traceroute/client/dist/*.whl

cat > "$config" <<EOF
[TESTLAB]
client="$client_env"/bin/augsburg-traceroute
server_v4=/reverse-traceroute/server/augsburg-traceroute-server-v4
server_v6=/reverse-traceroute/server/augsburg-traceroute-server-v6
EOF

mkdir results && pushd results
python3 /reverse-traceroute/testlab/test.py "$config"
popd
cp -rf results /reverse-traceroute/testlab/
