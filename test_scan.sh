#!/bin/bash

IP=127.0.0.1
PORT=8080

echo "Attempting SYN scan..."
nmap -sS $IP -p $PORT

echo "Attempting CONN scan..."
nmap -sT $IP -p $PORT

echo "Attempting ACK scan..."
nmap -sA $IP -p $PORT

echo "Attempting NULL scan..."
nmap -sN $IP -p $PORT

echo "Attempting FIN scan..."
nmap -sF $IP -p $PORT

echo "Attempting XMAS scan..."
nmap -sX $IP -p $PORT

