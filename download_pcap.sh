#!/bin/bash

wget $1 && unzip -P infected ${1##*/}

