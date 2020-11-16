# P4-16 Source Code

In this repository, the prototype P4 source code is written in P4-16, and compiled using version 9.2.0 of BF_SDE. 

## PTF

We support PTF for your experiments on your server. Here are the steps:

1. In `bf-sde-9.2.0` directory, use the command `./p4_build.sh {Directory of this repository}/fcm.p4 -j4`  to build `fcm.p4`.
2. In `bf-sde-9.2.0` directory, use the command `./run_tofino_model.sh --arch tofino -p fcm`  to run Tofino model.
3. Concurrently, with another terminal, use the command `./run_switchd.sh --arch tofino -p fcm`
4. Concurrently, with another terminal, use the command `./run_p4_tests.sh --arch tofino -p fcm -t {Directory of this repository}/ptf` to add TCAM entries, generate and send packets, and get queries with error calculation.

The PTF python script is implemented on `ptf/test_fcm.py`. You can refer the hash calculations and cardinality estimation in `ptf/fcm_utils.py`. To use with the FCM simulator codes, you can change the hash functions in the simulator with c++ codes `ptf/hash_calc.cpp`. 


