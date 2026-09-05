#!/bin/sh
# Start-up hook mounted by the `init_mount` runtime-context variant.
# It performs no work beyond announcing itself: the point of the variant is that
# an attached start-up directory changes which processes the container executes,
# which is exactly the contrast the profile-scope study needs to measure.
echo "porygon study init hook"
