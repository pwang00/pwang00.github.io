gem uninstall libv8-node  # to get rid of musl version
bundle lock --add-platform x86_64-linux
gem update --system  # not sure if necessary but I didn't try again without it
bundle update --bundler
