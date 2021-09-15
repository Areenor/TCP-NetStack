# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.18

# Default target executed when no arguments are given to make.
default_target: all

.PHONY : default_target

# Allow only one "make -f Makefile2" at a time, but pass parallelism.
.NOTPARALLEL:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Disable VCS-based implicit rules.
% : %,v


# Disable VCS-based implicit rules.
% : RCS/%


# Disable VCS-based implicit rules.
% : RCS/%,v


# Disable VCS-based implicit rules.
% : SCCS/s.%


# Disable VCS-based implicit rules.
% : s.%


.SUFFIXES: .hpux_make_needs_suffix_list


# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /snap/cmake/599/bin/cmake

# The command to remove a file.
RM = /snap/cmake/599/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/richard/CLionProjects/anpnetstack

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/richard/CLionProjects/anpnetstack

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target install/strip
install/strip: preinstall
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Installing the project stripped..."
	/snap/cmake/599/bin/cmake -DCMAKE_INSTALL_DO_STRIP=1 -P cmake_install.cmake
.PHONY : install/strip

# Special rule for the target install/strip
install/strip/fast: preinstall/fast
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Installing the project stripped..."
	/snap/cmake/599/bin/cmake -DCMAKE_INSTALL_DO_STRIP=1 -P cmake_install.cmake
.PHONY : install/strip/fast

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake cache editor..."
	/snap/cmake/599/bin/ccmake -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : edit_cache

# Special rule for the target edit_cache
edit_cache/fast: edit_cache

.PHONY : edit_cache/fast

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/snap/cmake/599/bin/cmake --regenerate-during-build -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : rebuild_cache

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache

.PHONY : rebuild_cache/fast

# Special rule for the target list_install_components
list_install_components:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Available install components are: \"Unspecified\""
.PHONY : list_install_components

# Special rule for the target list_install_components
list_install_components/fast: list_install_components

.PHONY : list_install_components/fast

# Special rule for the target install/local
install/local: preinstall
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Installing only the local directory..."
	/snap/cmake/599/bin/cmake -DCMAKE_INSTALL_LOCAL_ONLY=1 -P cmake_install.cmake
.PHONY : install/local

# Special rule for the target install/local
install/local/fast: preinstall/fast
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Installing only the local directory..."
	/snap/cmake/599/bin/cmake -DCMAKE_INSTALL_LOCAL_ONLY=1 -P cmake_install.cmake
.PHONY : install/local/fast

# Special rule for the target install
install: preinstall
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Install the project..."
	/snap/cmake/599/bin/cmake -P cmake_install.cmake
.PHONY : install

# Special rule for the target install
install/fast: preinstall/fast
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Install the project..."
	/snap/cmake/599/bin/cmake -P cmake_install.cmake
.PHONY : install/fast

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start /home/richard/CLionProjects/anpnetstack/CMakeFiles /home/richard/CLionProjects/anpnetstack//CMakeFiles/progress.marks
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /home/richard/CLionProjects/anpnetstack/CMakeFiles 0
.PHONY : all

# The main clean target
clean:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 clean
.PHONY : clean

# The main clean target
clean/fast: clean

.PHONY : clean/fast

# Prepare targets for installation.
preinstall: all
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall

# Prepare targets for installation.
preinstall/fast:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall/fast

# clear depends
depend:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 1
.PHONY : depend

#=============================================================================
# Target rules for targets named anpnetstack

# Build rule for target.
anpnetstack: cmake_check_build_system
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 anpnetstack
.PHONY : anpnetstack

# fast build rule for target.
anpnetstack/fast:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/build
.PHONY : anpnetstack/fast

src/LinkedList.o: src/LinkedList.c.o

.PHONY : src/LinkedList.o

# target to build an object file
src/LinkedList.c.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/LinkedList.c.o
.PHONY : src/LinkedList.c.o

src/LinkedList.i: src/LinkedList.c.i

.PHONY : src/LinkedList.i

# target to preprocess a source file
src/LinkedList.c.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/LinkedList.c.i
.PHONY : src/LinkedList.c.i

src/LinkedList.s: src/LinkedList.c.s

.PHONY : src/LinkedList.s

# target to generate assembly for a file
src/LinkedList.c.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/LinkedList.c.s
.PHONY : src/LinkedList.c.s

src/anp_netdev.o: src/anp_netdev.c.o

.PHONY : src/anp_netdev.o

# target to build an object file
src/anp_netdev.c.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/anp_netdev.c.o
.PHONY : src/anp_netdev.c.o

src/anp_netdev.i: src/anp_netdev.c.i

.PHONY : src/anp_netdev.i

# target to preprocess a source file
src/anp_netdev.c.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/anp_netdev.c.i
.PHONY : src/anp_netdev.c.i

src/anp_netdev.s: src/anp_netdev.c.s

.PHONY : src/anp_netdev.s

# target to generate assembly for a file
src/anp_netdev.c.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/anp_netdev.c.s
.PHONY : src/anp_netdev.c.s

src/anpwrapper.o: src/anpwrapper.c.o

.PHONY : src/anpwrapper.o

# target to build an object file
src/anpwrapper.c.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/anpwrapper.c.o
.PHONY : src/anpwrapper.c.o

src/anpwrapper.i: src/anpwrapper.c.i

.PHONY : src/anpwrapper.i

# target to preprocess a source file
src/anpwrapper.c.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/anpwrapper.c.i
.PHONY : src/anpwrapper.c.i

src/anpwrapper.s: src/anpwrapper.c.s

.PHONY : src/anpwrapper.s

# target to generate assembly for a file
src/anpwrapper.c.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/anpwrapper.c.s
.PHONY : src/anpwrapper.c.s

src/arp.o: src/arp.c.o

.PHONY : src/arp.o

# target to build an object file
src/arp.c.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/arp.c.o
.PHONY : src/arp.c.o

src/arp.i: src/arp.c.i

.PHONY : src/arp.i

# target to preprocess a source file
src/arp.c.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/arp.c.i
.PHONY : src/arp.c.i

src/arp.s: src/arp.c.s

.PHONY : src/arp.s

# target to generate assembly for a file
src/arp.c.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/arp.c.s
.PHONY : src/arp.c.s

src/icmp.o: src/icmp.c.o

.PHONY : src/icmp.o

# target to build an object file
src/icmp.c.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/icmp.c.o
.PHONY : src/icmp.c.o

src/icmp.i: src/icmp.c.i

.PHONY : src/icmp.i

# target to preprocess a source file
src/icmp.c.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/icmp.c.i
.PHONY : src/icmp.c.i

src/icmp.s: src/icmp.c.s

.PHONY : src/icmp.s

# target to generate assembly for a file
src/icmp.c.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/icmp.c.s
.PHONY : src/icmp.c.s

src/init.o: src/init.c.o

.PHONY : src/init.o

# target to build an object file
src/init.c.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/init.c.o
.PHONY : src/init.c.o

src/init.i: src/init.c.i

.PHONY : src/init.i

# target to preprocess a source file
src/init.c.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/init.c.i
.PHONY : src/init.c.i

src/init.s: src/init.c.s

.PHONY : src/init.s

# target to generate assembly for a file
src/init.c.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/init.c.s
.PHONY : src/init.c.s

src/ip_rx.o: src/ip_rx.c.o

.PHONY : src/ip_rx.o

# target to build an object file
src/ip_rx.c.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/ip_rx.c.o
.PHONY : src/ip_rx.c.o

src/ip_rx.i: src/ip_rx.c.i

.PHONY : src/ip_rx.i

# target to preprocess a source file
src/ip_rx.c.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/ip_rx.c.i
.PHONY : src/ip_rx.c.i

src/ip_rx.s: src/ip_rx.c.s

.PHONY : src/ip_rx.s

# target to generate assembly for a file
src/ip_rx.c.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/ip_rx.c.s
.PHONY : src/ip_rx.c.s

src/ip_tx.o: src/ip_tx.c.o

.PHONY : src/ip_tx.o

# target to build an object file
src/ip_tx.c.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/ip_tx.c.o
.PHONY : src/ip_tx.c.o

src/ip_tx.i: src/ip_tx.c.i

.PHONY : src/ip_tx.i

# target to preprocess a source file
src/ip_tx.c.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/ip_tx.c.i
.PHONY : src/ip_tx.c.i

src/ip_tx.s: src/ip_tx.c.s

.PHONY : src/ip_tx.s

# target to generate assembly for a file
src/ip_tx.c.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/ip_tx.c.s
.PHONY : src/ip_tx.c.s

src/route.o: src/route.c.o

.PHONY : src/route.o

# target to build an object file
src/route.c.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/route.c.o
.PHONY : src/route.c.o

src/route.i: src/route.c.i

.PHONY : src/route.i

# target to preprocess a source file
src/route.c.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/route.c.i
.PHONY : src/route.c.i

src/route.s: src/route.c.s

.PHONY : src/route.s

# target to generate assembly for a file
src/route.c.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/route.c.s
.PHONY : src/route.c.s

src/subuff.o: src/subuff.c.o

.PHONY : src/subuff.o

# target to build an object file
src/subuff.c.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/subuff.c.o
.PHONY : src/subuff.c.o

src/subuff.i: src/subuff.c.i

.PHONY : src/subuff.i

# target to preprocess a source file
src/subuff.c.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/subuff.c.i
.PHONY : src/subuff.c.i

src/subuff.s: src/subuff.c.s

.PHONY : src/subuff.s

# target to generate assembly for a file
src/subuff.c.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/subuff.c.s
.PHONY : src/subuff.c.s

src/tap_netdev.o: src/tap_netdev.c.o

.PHONY : src/tap_netdev.o

# target to build an object file
src/tap_netdev.c.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/tap_netdev.c.o
.PHONY : src/tap_netdev.c.o

src/tap_netdev.i: src/tap_netdev.c.i

.PHONY : src/tap_netdev.i

# target to preprocess a source file
src/tap_netdev.c.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/tap_netdev.c.i
.PHONY : src/tap_netdev.c.i

src/tap_netdev.s: src/tap_netdev.c.s

.PHONY : src/tap_netdev.s

# target to generate assembly for a file
src/tap_netdev.c.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/tap_netdev.c.s
.PHONY : src/tap_netdev.c.s

src/timer.o: src/timer.c.o

.PHONY : src/timer.o

# target to build an object file
src/timer.c.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/timer.c.o
.PHONY : src/timer.c.o

src/timer.i: src/timer.c.i

.PHONY : src/timer.i

# target to preprocess a source file
src/timer.c.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/timer.c.i
.PHONY : src/timer.c.i

src/timer.s: src/timer.c.s

.PHONY : src/timer.s

# target to generate assembly for a file
src/timer.c.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/timer.c.s
.PHONY : src/timer.c.s

src/utilities.o: src/utilities.c.o

.PHONY : src/utilities.o

# target to build an object file
src/utilities.c.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/utilities.c.o
.PHONY : src/utilities.c.o

src/utilities.i: src/utilities.c.i

.PHONY : src/utilities.i

# target to preprocess a source file
src/utilities.c.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/utilities.c.i
.PHONY : src/utilities.c.i

src/utilities.s: src/utilities.c.s

.PHONY : src/utilities.s

# target to generate assembly for a file
src/utilities.c.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/anpnetstack.dir/build.make CMakeFiles/anpnetstack.dir/src/utilities.c.s
.PHONY : src/utilities.c.s

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... edit_cache"
	@echo "... install"
	@echo "... install/local"
	@echo "... install/strip"
	@echo "... list_install_components"
	@echo "... rebuild_cache"
	@echo "... anpnetstack"
	@echo "... src/LinkedList.o"
	@echo "... src/LinkedList.i"
	@echo "... src/LinkedList.s"
	@echo "... src/anp_netdev.o"
	@echo "... src/anp_netdev.i"
	@echo "... src/anp_netdev.s"
	@echo "... src/anpwrapper.o"
	@echo "... src/anpwrapper.i"
	@echo "... src/anpwrapper.s"
	@echo "... src/arp.o"
	@echo "... src/arp.i"
	@echo "... src/arp.s"
	@echo "... src/icmp.o"
	@echo "... src/icmp.i"
	@echo "... src/icmp.s"
	@echo "... src/init.o"
	@echo "... src/init.i"
	@echo "... src/init.s"
	@echo "... src/ip_rx.o"
	@echo "... src/ip_rx.i"
	@echo "... src/ip_rx.s"
	@echo "... src/ip_tx.o"
	@echo "... src/ip_tx.i"
	@echo "... src/ip_tx.s"
	@echo "... src/route.o"
	@echo "... src/route.i"
	@echo "... src/route.s"
	@echo "... src/subuff.o"
	@echo "... src/subuff.i"
	@echo "... src/subuff.s"
	@echo "... src/tap_netdev.o"
	@echo "... src/tap_netdev.i"
	@echo "... src/tap_netdev.s"
	@echo "... src/timer.o"
	@echo "... src/timer.i"
	@echo "... src/timer.s"
	@echo "... src/utilities.o"
	@echo "... src/utilities.i"
	@echo "... src/utilities.s"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system

