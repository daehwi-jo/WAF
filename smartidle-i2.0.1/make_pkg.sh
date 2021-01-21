#!/bin/bash

if [ -z "$1" ]
then
    echo -n "[Input] pkg-base name " # -n 옵션은 뉴라인을 제거해 줍니다.
    read pkg_name
else
    echo "[Info] pkg-base name : $1"
    pkg_name=$1
fi

if [ -z "$2" ]
then
    echo "[info] pkg make name $pkg_name" # -n 옵션은 뉴라인을 제거해 줍니다.
else
    echo "[make] pkg make name $2"
    pkg_name=$2
fi

cp -rf ./public pkg/$pkg_name/
cp -rf ./templates pkg/$pkg_name/
cp -f  ./$1 pkg/$pkg_name/$pkg_name
strip pkg/$pkg_name/$pkg_name

echo "[info] done pkg makeing (name $pkg_name)"
