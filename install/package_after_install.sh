#!/bin/bash

if command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload

	if systemctl is-active --quiet dae.service; then
		if ! systemctl restart dae.service; then
			exit 1
		fi
		echo "Restarting dae service, it might take a while."
	fi
fi
