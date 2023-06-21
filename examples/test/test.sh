# falco -o plugins[0].name=cpptest -o plugins[0].library_path=/home/vagrant/dev/jasondellaluce/plugin-sdk-cpp/examples/test/libtest.so -o load_plugins[0]=cpptest --list
# ./program
# falco -o plugins[0].name=cpptest -o plugins[0].library_path=/home/vagrant/dev/jasondellaluce/plugin-sdk-cpp/examples/test/libtest.so -o load_plugins[0]=cpptest --plugin-info=cpptest

sysdig -r /home/vagrant/downloads/syscall.scap -H /home/vagrant/dev/jasondellaluce/plugin-sdk-cpp/examples/test/libtest.so -p "*num=%evt.num cpp.field=%cpp.field" "evt.num >= 95000"
