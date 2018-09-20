# A guide for contributors

While you have gone through 'how to contribute' guides, if you are
not sure what to work on, but really want to help the project, you
have landed on the right document :-)

### Basic

We recommend a constant, continuous flow of improvements for the
project, than a patch which fixes **all** the below issues. It is
recommended you pick 1 file (or just few files) at a time to address
bellow issues.

Pick any `.c` file, and you can send a patch which fixes **any** of
the below themes. Ideally, fix all such occurrences in the file, even
though, the reviewers would review even a single line change patch
from you.

1. Check for variable definitions, and if there is a major 'stack'
consumptions due to variable declarations at the top of the function,
see if you can re-scope the variable to relevant sections (if it helps).

Most of the time, it would be for 'error' handling, most of these
variables are defined.

** TODO ** Add a sample or give a reference to existing patch.

2. Check for complete string initialization, compared to just '\0' at
the beginning. Fix it across the file.

Example:

`char new_path_name[PATH_MAX] = {0};` to `char new_path_name[PATH_MAX] = "";`

TODO: is there a reference patch already?

3. Change 'calloc()' to 'malloc()' wherever it makes sense.

In a case of allocating a structures, where you expect certain (or most of)
variables to be 0 (or NULL), it makes sense to use calloc(). But otherwise,
there is an extra cost of memset() the whole object after allocating it.
While it is not 'significant' improvement in performance, a code which gets
hit 1000s of times in second, it would surely add some value.

TODO: Refer one of Yaniv's patch here!

4. You can consider using snprintf(), instead of strncpy() while dealing
with strings.

While most of the string operations in the code is on array, and larger
size than required, strncpy() does an extra copy of 0s at the end of
string till the size of the array. It makes sense to use snprintf(),
which doesn't suffer with that behavior.

TODO: Refer one of Yaniv's patch here!

5. Now, pick a `.h` file, and see if a structure is very large, and see
if re-aligning them as per [coding-standard]() gives any size benefit,
if yes, go ahead and change it. Make sure you check all the structures
in the file for similar pattern.

TODO: Get link of coding-standard which defines this.

### If you are up for more :-)

Good progress! Glad you are interested to know more. We are surely interested
in next level of contributions from you!

#### Coverity

Visit [Coverity Dashboard](https://scan.coverity.com/projects/gluster-glusterfs?tab=overview).

Now, if the number of defect is not 0, you have an opportunity to contribute.

You get all the detail on why the particular defect is mentioned there, and
most probable hint on how to fix it. Do it!

TODO: give details about bugs and other things around coverity

#### Clang-Scan

Clang-Scan is a tool which scans the .c files and reports the possible issues,
similar to coverity, but a different tool. Over the years we have seen, they
both report very different set of issues, and hence there is a value in fixing it.

GlusterFS project gets tested with clang-scan job every night, and the report is
posted in the [job details page](). As long as the number is not 0 in the report
here, you have an opportunity to contribute! Similar to coverity dashboard, click
on 'Details' to find out the reason behind that report, and send a patch.


### I am good with programming, I would like to do more than above!

#### Lock regions / Critical sections

In the file you open, see if the lock is taken only to increment or decrement
a flag, counter etc. If yes, then recommend you to convert it to ATOMIC locks.
It is simple activity, but, if you know programing, you would know the benefit
here.

TODO: add a patch which shows this.

#### ASan (address sanitizer)

The job runs regression with asan builds, and you can also run glusterfs with
asan on your workload to identify the leaks. If there are any leaks reported,
feel free to check it, and send us patch.

You can also run `valgrind` and let us know what it reports.

#### Porting to different architecture

This is something which we are not focusing right now, happy to collaborate!


### I don't know C, but I am interested to contribute in some way!

You are most welcome! Our community is open for your contribution! First thing
which comes to our mind is **documentation**. Next is, **testing** or validation.

If you have some hardware, and want to run some performance comparisons with
different version, or options, and help us to tune better is also a great help.

#### Documentation

1. We have some documentation in [glusterfs repo](../), go through these, and
see if you can help us to keep up-to-date.

2. The https://docs.gluster.org is powered by https://github.com/gluster/glusterdocs
repo. You can check out the repo, and help in keeping that up-to-date.

3. Our website (https://gluster.org) is maintained by https://github.com/gluster/glusterweb
repo. Help us to keep this up-to-date, and add content there.

4. Write blogs about Gluster, and your experience, and make world know little
more about Gluster, and your use-case, and how it helped to solve the problem.


#### Testing

1. There is a regression test suite in glusterfs, which runs with every patch, and is
triggered by just running `./run-tests.sh` from the root of the project repo.

You can add more test case to match your use-case, and send it as a patch, so you
can make sure all future patches in glusterfs would keep your usecase intact.

2. Glusto-Tests: This is another testing framework written for gluster, and makes
use of clustered setup to test different use-cases, and helps to validate many bugs.

#### Ansible

Gluster Organization has rich set of ansible roles, which are actively maintained.
Feel free to check them out here - https://github.com/gluster/gluster-ansible

#### Monitoring

We have prometheus repo, and are actively working on adding more metrics. Add what
you need @ https://github.com/gluster/gluster-prometheus

#### Health-Report

This is a project, where at any given point in time, you want to run some set of commands locally, and get an output to analyze the status, it can be added. Contribute @ https://github.com/gluster/gluster-health-report

### All these C/bash/python is old-school, I want something in containers.

We have something for you too :-)

Please visit our https://github.com/gluster/gcs repo for checking how you can help,
and how gluster can help you in container world.


### Note

For any queries, best way is to contact us through mailing-list.
