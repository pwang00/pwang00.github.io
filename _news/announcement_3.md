---
layout: post
title: Improving Manticore state awareness with Ansible and DigitalOcean
date: 2020-01-26 16:11:00-0400
inline: false
---

During my 2019-2020 Trail of Bits winternship, I helped improve [Manticore’s](https://github.com/trailofbits/manticore) versatility and functionality. Specifically, I combined it with Ansible (an automated provisioning framework) and Protobuf (a serialization library) to allow users to run Manticore in the cloud and better understand what occurs during a Manticore run.

As it stands, Manticore is very CPU-intensive; it competes for CPU time with other user processes when running locally. Running a job on a remotely provisioned VM in which more resources could be diverted to a Manticore run would make this much less of an issue.

To address this, I created “mcorepv” (short for Manticore Provisioner), a Python wrapper for Manticore’s CLI and Ansible/DigitalOcean that allows users to select a run destination (local machine/remote droplet) and supply a target Manticore Python script or executable along with all necessary runtime flags. If the user decides to run a job locally, mcorepv executes Manticore analysis in the user’s current working directory and logs the results.

Things get more interesting if the user decides to run a job remotely—in this case, mcorepv will call Ansible and execute a playbook to provision a new DigitalOcean droplet, copy the user’s current working directory to the droplet, and execute Manticore analysis on the target script/executable. While the analysis is running, mcorepv streams logs and Manticore’s stdout back in near real time via Ansible so a user may frequently check on the analysis’ progress.

Manticore should also simultaneously stream its list of internal states and their statuses (ready, busy, killed, terminated) to the user via a protobuf protocol over a socket in order to better describe the analysis’ status and resource consumption (this is currently a work in progress). To make this possible, I developed a protobuf protocol to represent Manticore’s internal state objects and allow for serialization, along with a terminal user interface (TUI). Once started on the droplet, Manticore spins up a TCP server that provides a real-time view of the internal state lists. The client can then run the TUI locally, which will connect to the Manticore server and display the state lists. Once the job has finished, the Manticore server is terminated, and the results of the Manticore run along with all logs are copied back to the user’s local machine where they may be further inspected.

There’s still some work to be done to ensure Manticore runs bug-free in the cloud. For example:

* Port forwarding must be set up on the droplet and local machine to ensure Manticore’s server and client TUI can communicate over SSH.
* The TUI needs additional optimization and improvement to ensure the user gets the right amount of information they need.
* mcorepv and its Ansible backend need to be more rigorously tested to ensure they work properly.

I’m glad that in my short time at Trail of Bits, I was able to help move Manticore one step closer to running anywhere, anytime.  

<figure>
<img src="../diagram.webp" alt="diagram" width="700"/>
<figcaption>Fig 1: Proof of concept—Manticore TUI displaying a list of state objects and log messages to the user.</figcaption>
</figure>
* [Manticore Provisioner](https://github.com/trailofbits/mc-ansible)
* [Original blog post link](https://blog.trailofbits.com/2020/05/22/emerging-talent-winternship-2020-highlights/)
