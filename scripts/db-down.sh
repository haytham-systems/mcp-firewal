#!/usr/bin/env bash
mysqladmin -uroot -h127.0.0.1 -P"${MYSQL_PORT:-3307}" shutdown && echo "mcp-firewall dev mysql stopped"
