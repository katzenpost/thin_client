# SPDX-License-Identifier: AGPL-3.0-only

katzenpost_ref?=91debb67407dd6f8bc9a7e58c9613dc30cc4699c
katzenpost_dir?=.katzenpost
live_dir?=.live
connect_deadline?=480

.PHONY: check-live clean-live

check-live:
	katzenpost_ref=$(katzenpost_ref) katzenpost_dir=$(katzenpost_dir) \
	live_dir=$(live_dir) connect_deadline=$(connect_deadline) \
	./check-live.sh

clean-live:
	rm -rf $(live_dir)
