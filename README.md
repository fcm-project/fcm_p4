# FCM-Sketch: Generic Network Measurements with Data Plane Support

## P4 Source Code
This repository includes the P4 implementation of the CoNEXT 2020 paper [*FCM-Sketch: Generic Network Measurements with Data Plane Support*](https://www.comp.nus.edu.sg/~songch/papers/conext20_fcmsketch.pdf).

Currently, the prototype P4 source code is written in both P4-14 and P4-16, and compiled using version 8.2.0 and 9.2.0 of BF_SDE, respectively.

## Measurement
FCM-Sketch supports both various in-network (data-plane) and control-plane queries.
- Data-plane queries:
    - `Flow size estimation`
    - `Heavy hitter detection`
    - `Cardinality`
- Control-plane queries:
    - `Flow size distribution`
    - `Entropy`

In addition, `Heavy change detection` is avaialble entirely in the data plane if we keep multiple sketches with resource trade-off.

## Compile & Test
Please use the description in the corresponding directory.

## Future Update plane
Data-Plane queries are supported in P4-16 implementation. In future, we will provide a PTF test for EM-algorithm. Actually, it is easy to extend; we can load register values, sync with simulator's data structures, and run the algorithm.

## Citing FCM-Sketch

You can cite this repository or FCM-Sketch as

    @inproceedings{song2020fcm,
      title={FCM-sketch: generic network measurements with data plane support},
      author={Song, Cha Hwan and Kannan, Pravein Govindan and Low, Bryan Kian Hsiang and Chan, Mun Choon},
      booktitle={Proceedings of the 16th International Conference on emerging Networking EXperiments and Technologies},
      pages={78--92},
      year={2020}
    }
