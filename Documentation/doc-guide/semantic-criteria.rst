# Linux Kernel Requirements Template


## Introduction

As part of a broader effort to document the architecture and design of the Linux Kernel, we propose a method to formally describe developer intent at the function and subfunction level in the form of testable expectations (i.e. requirements). This will provide a fact based foundation for pass/fail test development, test validation via code coverage tools, support optional traceability to higher level design, and enable tool development for process management.


## Background Information

During the 2024 Linux Plumbers conference, a discussion [1] on Linux Kernel design spun out of the Safe Systems mini-conference [2]. This culminated in a general agreement that low level developer intent (requirements) needed to be maintained in-line with code, and that a machine readable template was required to ensure consistency and support automation.

If one thinks of code as the “what”, the “why” is a reflection of developer intent, usually in service to an agreed upon design or architecture. The “why” typically begins as human inspiration and eventually finds its way into commit messages, mailing lists, conference proceedings, papers, and a long tail of mediums far too numerous to mention.

The “why” gives the “what” its purpose, and only with a clear understanding of purpose can we reliably assess how well the implementation matches up with the intended outcome. The opposite is also true. Without a clear understanding of developer intent, interpretation and assessment is just a guess.


As a general rule, developer intent at the lowest levels tends to be lost during the development process. This contributes to a lack of testable expectations, known as “low level requirements” (LLR), at the function and subfunction level.

Anyone who wishes to assess such an implementation must dig through the aforementioned sources to, “condense fact from the vapor of nuance” (Neal Stephenson, Snow Crash). Others who wish to perform similar assessments must repeat this work with a low likelihood of alignment in the unlikely event a comparison is even possible. \


In many (most?) situations it may be possible to produce an educated guess, but that guess typically lacks any form of documented review by persons with relevant authority and expertise.

As a general rule, authority and expertise are understood to be a combination of the kernel developer community and those with requirement writing expertise. It is not always the case that good developers make good requirement writers and vice versa. Nor is it always the case that developers have the time or interest to document their code at such a low level. Therefore, along with a strong desire to avoid additional process that slows down development, this points to a need for separate, but complementary, maintainership paths.

[1] https://www.youtube.com/watch?v=stqGiy85s_Y

[2] https://lpc.events/event/18/sessions/187/#20240920


## Cui Bono? / Who Benefits?

Beyond the obvious benefits to the Linux Kernel developer community, a number of working groups, such as ELISA and SPDX as well as a broad set of industry OEMs, have a vested interest in supporting the ability to trace high level design to low level requirements (LLR) that accurately reflect developer intent.

The aerospace standard (DO-178C) requires LLRs for projects in the high criticality (SWL A-C) range and describes them as, “software requirements from which Source Code can be directly implemented without further information”.

FAA report TC-15/27 [1] articulates concerns regarding the development of low level requirements in an existing project like the Linux kernel: \



    “In [a reverse engineering (RE)] process, the LLRs may be developed from source code without due regard to the difference in the abstraction level and the resulting LLRs being too similar to the code (e.g., pseudocode). Because such translations may be performed with little intellectual effort or understanding of the code’s intent, these [low effort] practices should not be permitted on RE projects because they do not provide the same level of confidence as a forward engineering process.


    The difference between abstraction levels should demonstrate some level of understanding, either by differences in the representations or the provision of additional information, such as context information or rationale between HLR and LLR mapping.” \


In his “Avionics Linux” paper presented at the 2023 IEEE DASC (Digital Aviation Software Conference) [2], Steve VanderLeest summarizes the concerns noted in FAA TC-15/27 and hints at the need for an approach similar to the one being proposed in this document:


    “Thus the reverse engineering cannot simply repeat the code, but must infer its purpose. Furthermore, this report hints that understanding of intent is further demonstrated by weaving together LLRs from the code (bottom up) with HLRs decomposed from system requirements (top down)”.

The automotive industry is regulated by ISO 26262, which tends to be far less prescriptive when compared to the aerospace industry standard. Clause 8.4.4. of ISO 26262-6 states:


    “The specification of the software units shall describe the functional behaviour and the internal design to the level of detail necessary for their implementation.”

ISO-PAS-8296 addresses use of pre-existing software (such as the Linux kernel), and is supplemental to reuse guidance in ISO-26262-8 Section 12. \

Analysis of the Safety Integrity Standard expectations, generally from an automotive context, has been pursued by the ELISA Safety Architecture Working Group. This includes current Linux Kernel Documentation templates and how the associated development and maintenance processes stand against them. Their current investigational results can be found in the ELISA Safety Architecture github repository [3]. \

The intent of this proposal can be summarized as the pursuit of a strategy that is beneficial to a broad set of interested parties. The Linux Kernel developer community stands to benefit to the greatest degree as the kernel source code gains significant scrutiny and testing that it currently lacks. Aerospace OEMs will see the fulfillment of a basic criteria that has consistently kept Linux out of high criticality spaces. And as a subset of the rigor required for reuse, the automotive industry will also benefit significantly.


Having faith in this process as worthy of their support, participation is expected from a broad set of industry participants who stand to derive their own immediate benefit. \


[1] https://www.faa.gov/sites/faa.gov/files/aircraft/air_cert/design_approvals/air_software/TC-15-27.pdf

[2] https://ieeexplore.ieee.org/document/10311247

[3] https://github.com/elisa-tech/Safety_Architecture_WG


## A Virtuous Cycle

By adding requirements at the function or (where relevant) subfunction level, one enables the creation of a virtuous cycle when testing is supplemented with open source code coverage tools like llvm-cov and Gcov.

As a true reflection of developer intent, a requirement informs the creation of a pass/fail test which can then be assessed with code coverage tools. A failing test may indicate broken code or a requirement that fails to capture developer intent. A gap in code coverage may indicate a missing requirement, unintended functionality, or an insufficient test procedure. 

With requirement, test, and coverage in equilibrium, it becomes possible to assert that the code is an accurate reflection of developer intent. But it is important to recognize that this equilibrium says little beyond developer intent; code that behaves as intended can still be the product of poor design.

In order to improve design and architecture, implementations must first quantifiably align with developer intent. Without such alignment, it is impossible to accurately discern the difference between bad design and poor implementation.


## Template Goals

We establish the following desirable outcomes.



1. The syntax should enforce unique IDs, traceability, configuration management, and change management, such that automation stands a high likelihood of generating a complete requirement document tailored to individual needs.
2. Should be maintainable together with the code.
3. Should support hierarchical traceability to allow refinement of SW dependencies (i.e. cross reference critical APIs or data structures from the template).
4. Should describe error conditions and success behavior. This includes cases where success is returned yet behavior diverges from expectations (e.g. cover tricky corner cases).
5. Should allow covering both static and dynamic aspects of the code.
6. Should be compatible with existing documentation templates such as kernel-doc [0], manpage [1], Glibc, and Linux Kernel ABI [2]. 
7. Should support the definition of a test plan (i.e. syntax should enforce testability as well as the avoidance of untestable “shall not” type requirements).

[0] https://www.kernel.org/doc/html/latest/doc-guide/kernel-doc.html

[1] https://man7.org/linux/man-pages/man7/man-pages.7.html

[2] https://www.kernel.org/doc/Documentation/ABI/README


## Template Requirements

The use of “should” refers to design elements that are desirable, but not strictly enforceable or verifiable. The use of “shall” refers to design elements that must be formally and verifiably satisfied.



* Should avoid substantive changes to current Linux Kernel development processes.
    * **Note:** In general, the historical Linux kernel development pattern has been to write code first and document it later. As such, we expect that requirements will typically lag development. The “code first” development paradigm is considered a feature, and is factored into the requirements development process outlined in this document.
* Shall enable a requirements maintainership role that is separate from, but complimentary to, the traditional subsystem maintainer role.
    * **Note:** Subsystem maintainers should not be precluded from writing and maintaining their own requirements. However, writing a good statement of testable intent that avoids ambiguities and common pitfalls (e.g. looking suspiciously like pseudocode) requires certain skills that not everyone has. Some form of oversight/sign-off validation may be necessary.
* Each requirement shall have an immutable ID.
* Each requirement shall have a mutable Hash Key.
* Stable IDs and Hash Keys:
    * Shall be globally unique (e.g. SHA-256)
    * Shall be generated without central coordination.
    * Shall be reproducible (i.e. generated in a standard way).
* Requirement maintainer shall update the Hash Key when relevant code or requirement wording is changed.
    * Note 1: The Git commit log will keep a record of the change to support manual and automated analysis (e.g. impact analysis, re-establishing traceability, etc).
    * Note 2: While hash generation can be done by hand, it is expected to be automated in order to avoid human error.
* Requirement template shall be embedded with the relevant code. (e.g. comment just above the implementation).
* The template format:
    * Shall be machine readable.
    * Should be compact and succinct to avoid unnecessary clutter.
    * Should be easy to read and biased against complex formatting.
    * Shall be standardized (e.g. through SPDX) to support use in other OSS projects.
    * Shall detect when relevant code changes, including movement to a different file.
        * Note 1: Detection refers to Hash Key generation that no longer matches the current Hash Key.
        * Note 2: Movement to a different file may indicate a modification of intent which warrants a review. Movement within a file should _not_ trigger a review unless the relevant code itself has changed.
    * Shall detect when requirement wording changes.
        * Note: Detection refers to Hash Key generation that no longer matches the current Hash Key.
    * Shall use the stable ID as the sole method for tracing _to_ other requirements.
        * Note: Tracing _from_ is explicitly not supported because it makes requirement reuse impossible or overly complex. If bidirectional tracing is needed, tools can generate the necessary graphs based on individual needs.
    * Shall support being referenced from other systems.
        * Note: This refers to test frameworks, proprietary OEM projects, etc. The intention is to avoid any form of coupling or forced interaction, while still enabling consistent traceability.
    * Should support report generation, documentation generation, and various forms of analysis.


## Semantic Quantization

&lt;For the purposes of establishing the level of information a requirement is expected to convey, this section should go into detail on the way semantic meaning is quantized at different levels. E.g. source code, machine code, requirements, etc. The idea is to convey that (like energy levels in quantum physics), information is only reasonably expressed at certain discrete levels. Source code is a discrete level, assembly code is a discrete level, machine code is a discrete level, low level requirements are a discrete level, high level requirements are a discrete level, and so on.>


## Proposed Template


### Terminology

&lt;Add detail on basic terminology - e.g. template vs. requirement, the meaning of “sidecar”, etc..Also note that terminology will be described in greater detail in the following sections, so this section should be used for reference.>


### Usage

It should be possible to describe a function or preprocessor directive with a single low level requirement (LLR) when the function or directive is of manageable complexity. Deviations, such as splitting functionality over multiple LLRs or combining multiple functions into a single LLR, negatively impact maintenance and testing efforts and should be considered only after all other reasonable options have been exhausted.

Where code cannot be broken up or otherwise refactored due to existing constraints, subfunction or stacked requirements _might_ be warranted as a last resort. The ordering of stacked requirements is arbitrary so long as each requirement remains independent and unambiguous.


### General Detail

This template was inspired by the SPDX license nomenclature, examples of which are found here [0] and here [1].


Each line consists of a tag prefixed with “SPDX-Req-” followed by a string. In addition to ensuring a consistent namespace, the SPDX-Req prefix allows for a recursive grep to find all requirement information project-wide.

All characters shall be UTF-8, and no text processing, escapes, or variable expansion semantics are defined. Tags are always followed by a “:” (0x3A) and a space (0x20) or underscore “_” (0x5F). Strings begin on the second character after the colon “:” found at the end of each tag and end just prior to a newline (0xA).

Line length should comply with the generally accepted 80 character common sense rule [2]. Leading whitespace is preserved, trailing whitespace shall always be removed per Linux Kernel patch submission guidelines [3].

Beyond the common cases associated with multi-line tags, the SPDX-Req specification takes no position on formatting except to discourage it. SPDX-Req is intended to be machine and human readable while avoiding unnecessary clutter that discourages participation.

[0] https://github.com/torvalds/linux/blob/master/LICENSES/preferred/GPL-2.0 \
[1] https://github.com/torvalds/linux/blob/master/kernel/sched/cpudeadline.c

[2] https://www.kernel.org/doc/html/latest/process/coding-style.html#breaking-long-lines-and-strings

[3] https://www.kernel.org/doc/html/latest/process/submitting-patches.html


### Supplemental Tags

This template must, first and foremost, serve the needs of the OSS projects that choose to adopt it. The proposed tag types and tag semantics were chosen on that basis. 

Many industries associate additional information with requirements, such as hazard (safety) and threat (security) impacts. This information is explicitly not included in this template, nor is it likely to be considered in the future. Supplemental information can be separately recorded yet uniquely associated with a requirement via the stable requirement ID.


### Multi-Line Tags

SPDX-Req-Text and SPDX-Req-Note are examples of multi-line tags.

The intention is to make the common case easy, which is typically one or more sentences that can be rendered into formal documentation by simple string concatenation. A leading space may need to be added to subsequent lines to ensure concatenation produces the desired result.

The slightly less common case involves ASCII art, such as tables and lists. A combination of spaces and tabs can be used to manage formatting, and an underscore “_” (0x5F) can be added just after the tag colon “:” to tell tools to add an intentional newline (0xA) after concatenating the current string.


### Hash Generation Method

The SPDX-Req-ID and SPDX-Req-HKey tag strings are reproducible hashes that satisfy uniqueness and independence constraints. 

Hashes are produced based on the following criteria:



* PROJECT:	The name of the project (e.g. linux)
* FILE_PATH:	The file the code resides in, relative to the root of the project repository.
* INSTANCE:	The requirement template instance, minus tags with hash strings.
* CODE:		The code that the SPDX-Req applies to.

The hash string is then generated as a basic string concatenation: \

`echo -nE "${PROJECT}${FILE_PATH}${INSTANCE}${CODE}" | sha256sum`

This method is based on a thought experiment that begins by making the unreasonable assumption that we have an optimal architecture and that all code is in perfect alignment with developer intent as demonstrated by a stable equilibrium of the virtuous cycle (requirement, test, and code coverage). We then choose an arbitrary requirement and its associated code, and challenge ourselves to define the minimum criteria, such that if any single element were to change, we should be concerned that the requirement no longer accurately reflects the implementation.

With all things stable except for the localized change, we are led to the minimal set of criteria defined above. We summarize that criteria as a complete unit of semantic meaning. Using the proposed hashing method, we gain the ability to track and compare complete units of semantic meaning.


### Template Instantiation Rules

When instantiating a template, the following rules must be observed.



* The first line must always be an SPDX-Req-ID tag.
* The ordering of SPDX-Req lines shall always be retained.
* SPDX-Req lines for a given instantiation must be grouped together and not interrupted.
* Other than SPDX-Req-ID, ordering of tag types is up to the discretion of the requirement maintainer. However, for consistency it is recommended that the order defined in the tag index be used.

Only `SPDX-Req-ID, SPDX-Req-Text` and `SPDX-Req-Note `should be embedded in the Linux Kernel source, the other fields shall be maintained externally in separate files to avoid cluttering the source code. `SPDX-Req-ID` is the identifier used to bind the SPDX fields implemented in the source code with the rest implemented in a side file.


### Tag Index

Detailed information on each tag is found in subsequent sections.


### SPDX-Req-ID



* This tag is mandatory.
* This tag must reside with the code.

The tag string is a hash generated using the Hash Generation Method. This string is stable and does not change over the life of the template instance.

Requirement tracing is dependent on the stability of the tag string (see also: SPDX-Req-Child).


### SPDX-Req-End

This tag is mandatory.


### SPDX-Req-HKey

This tag is mandatory.

The tag string is a hash generated using the Hash Generation Method. At template instance creation time, this value will be equal to the SPDX-Req-ID. This value will be updated whenever a change is made to one of the Hash Generation Method criteria.

The intent of this tag is to enable a programmable method for detecting when a requirement needs to be reviewed, and documenting the completion of that review. This functionality must be separate from the SPDX-Req-ID tag to avoid triggering hash updates to requirements that trace to the changed requirement (see also: SPDX-Req-Child).

A useful analogy for understanding the intent of this tag is to consider why it is bad practice to commit code that is commented out. There is no practical way to test or assess correctness and relevancy of commented code, so it is necessary to remove it to avoid ambiguity.

Since there is no programmatic way to confirm valid alignment between code, requirement, and developer intent, a manual review step is required to avoid similar forms of ambiguity. However, it is also necessary to enable asynchronous development of requirements and code because OSS is not a closed corporate environment. Therefore we need a way to automate the detection of review candidates and record the completion of a review.

It is reasonable to ask why we need a separate tag for this. Why not use existing functionality, like git blame?

This method solves multiple problems that are not addressed by tools like git blame.

Most importantly, updating the Hash Key generates an entry in the public record (e.g. git commit log) that a review has been done, including who did the review, when it was done, and who signed off on it (e.g. Signed-off-by, Acked-by, etc). Without this type of change record, there is no way to tell if any effort was made to maintain the required alignment.

Not all code is developed using Git, and source code is also occasionally tar’d up to create a versioned source bundle release. In both cases there would be no reliable way for the recipient to validate the relevant alignment. It is always possible for someone to “cheat” and run a script to update all of the Hash Keys without doing the validation work. But that type of dishonesty should be discoverable when tests and code coverage reveal poor alignment with requirement wording.

NOTE: while Hash Keys are a useful instrument that maintainers can leverage to make sure the requirement is aligned with code changes, on the other side maintainers shall not solely rely on the flags raised by changed Hash Keys as patchsets are submitted. \
For example in a scenario where a function without requirements is changed and the same is also invoked by another function which hasone with an associated requirement, the corresponding Hash Key of the last functionone would not be updated. \
Such a scenario is possible if the Kernel is in an intermediate state of requirement documentation or also if the function missing the requirement was not contributing to the safety requirement of the invoking function prior to the change (however after the change it could contribute to it or, most dangerously, violate it).

Even if all functions come with associated low level safety requirements it is possible that a function invoked by another one is not reflected in the “SPDX-Req-Child” requirement dependency (simply because the invoked function does not play any role with respect to the requirement associated with the invoking one) and yet a change in such invoked function could lead to a violation of the invoking function requirements: in this case the need to update “SPDX-Req-Child” with the new dependency and the need to review the invoked function change against the requirement of the invoking function would, again, not be flagged by any Hash Key change if the invoking function requirement.

In summary Hash Keys are a useful tool but maintainers should always be aware of the impact of changes on the subsystems and drivers behaviors.


### SPDX-Req-Sys

This tag is mandatory.

The tag string shall consist of a subsystem identifier. For the Linux Kernel, the subsystem identifier is found in the MAINTAINERS file and is equivalent to the first subsystem returned when the `--sections` argument is provided to `scripts/get_maintainer.pl`

The subsystem string is intended to support maintainers, similar to the way the subject line is used to inform patch submissions.


### SPDX-Req-Child

This tag is optional.

When a higher level requirement is decomposed into one or more lower level requirements, the higher level requirement uses one or more SPDX-Req-Child tags to document this connection. The tag string shall be a single valid SPDX-Req-ID with the limitation that tracing must always be acyclic (i.e. no loops).

Design decomposition is the process of decomposing high level ideas into progressively smaller ideas until they are discrete enough to implement in code, “without further information”. Requirements that trace _to_ other requirements are evidence of this type of decomposition.

Tracing in reverse, _from_ a lower level requirement to a higher level requirement is not supported in any explicit sense. Being explicit about this type of tracing would inhibit reuse. Much like the Linux Kernel itself, LLRs take no position on how they are included in higher level design intent. \
 \
Anyone that requires bidirectional tracing can trivially produce this information from their own decomposed design. If you know the _to_, you can easily figure out the _from_.

As an example this tag can be used to link the requirements associated with the relevant function dependencies.


### SPDX-Req-Text

This is a required multi-line tag.

Tag text is expected to be human readable and comply with requirement definition best practices. \
 \
Requirements describe developer intent in the form of pass/fail testable expectations. This includes relevant SW/HW state, input parameters, and configuration parameters. Low Level Requirements (LLR) should be detailed enough to support blind reimplementation without additional information, while avoiding a pseudocode-like repetition of the existing implementation.


### SPDX-Req-Note

This is an optional multi-line tag.

In order to avoid the creation of impenetrable legalese, requirements must occasionally be written in a manner that leaves them open to interpretation. Optional commentary notes can be included to close down incorrect avenues of interpretation. \
 \
Commentary notes do not “count” in any pass/fail testable sense, and it is incorrect to use them for any purpose other than to remove ambiguity from the requirement text.


### SPDX-Req-Ref

This is an optional multi-line tag.

Different parts of the code may participate in a requirement.   This is a way to link back to a defined requirement ID, rather than replicate the requirement text (and inadvertent variance).

SPDX-Req-Ref is expected to be used mostly for code not exclusively described by the SPDX-Req-ID associated with it and that instead needs to include additional expectations described in referenced IDs.


## Examples


```
// SPDX-Req-ID: <ID>
// SPDX-Req-HKey: <KEY>
// SPDX-Req-Child: <ID>
// SPDX-Req-Sys: <SUBSYSTEM>
// SPDX-Req-Lines: <LINES>
// SPDX-Req-Text: Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed
// SPDX-Req-Text:  do eiusmod tempor incididunt ut labore et dolore magna
// SPDX-Req-Text:  aliqua. Ut enim ad minim veniam, quis nostrud exercitation
// SPDX-Req-Text:  ullamco laboris nisi ut aliquip ex ea commodo consequat.
// SPDX-Req-Note: This is a typical explanatory note. It is not a requirement
// SPDX-Req-Note:  but it does add relevant context and clarity.
```


## 


## The What/Why/How of Source Code

The Linux Kernel, like most OSS projects, develops in a code driven fashion, rather than adopting a requirement driven approach, hence it is critical to identify the design elements of the code that must be documented and that such template(s) would apply to.

The design elements to be documented are the Linux Kernel drivers/subsystems mainly through the documentation of the respective interfaces. \
The main reason for doing this is to allow integrators to evaluate the expected behaviour of the code against the allocated requirements and developers to develop and verify code against the defined expected behaviour.

Below a summary of the current Kernel external and internal interfaces and how they are currently documented is presented.


### User Space Interfaces



* **Syscalls**: In terms of expected behavior both the manpage and the glibc manual provide a template for specifying it and all syscalls are documented within such a template. \
With respect to syscalls it is important to highlight which of them specify an implementation dependent behavior (e.g. open, read, write, ioctl, etc…), since they must be further specified by the drivers or subsystems associated with the input file descriptor.

    Syscalls are invoked by user space processes to initiate a specific Kernel behavior. \


* **Procfs, sysfs, debugfs and other user space interfaces **exposed by the Kernel are documented following the template defined in [https://www.kernel.org/doc/Documentation/ABI/README](https://www.kernel.org/doc/Documentation/ABI/README) 

    These file interfaces are created by the Kernel and are used by user space processes to initiate a specific Kernel behavior. \
In the template above right now the expected behavior can be described informally in the “Description” field.

* **Signals**: 

    These are software exceptions initiated by the kernel to trigger a specific response in a user space process.


    **TODO**: describe where to find the current documentation (e.g. [https://man7.org/linux/man-pages/man7/signal.7.html](https://man7.org/linux/man-pages/man7/signal.7.html))



### Kernel Space Interfaces

Kernel space code is developed and maintained according to different subsystems and drivers defined in the  [MAINTAINERs](https://github.com/torvalds/linux/blob/master/MAINTAINERS) file. \
The expected behavior associated with the interfaces exposed by such subsystems and drivers at the moment is eventually described:



* Informally directly in the rst files of the Linux Kernel Documentation [repo](https://github.com/torvalds/linux/tree/master/Documentation)
* Informally embedding the [Overview](https://www.kernel.org/doc/html/latest/doc-guide/kernel-doc.html#overview-documentation-comments) section into the source code of drivers and subsystems
* Formally following the[ kernel-doc](https://www.kernel.org/doc/html/latest/doc-guide/kernel-doc.html) format


## Semantic aspects of the template(s)

From a semantic point of view it is important to document the intended or expected behavior (from a developer or integrator point of view respectively) in consideration of the different design aspects impacting it.

Such behavior shall be described in a way that makes it possible to define test cases unambiguously. \
To this extent it is important to document design elements impacting the expected behavior and the design elements impacted by the expected behavior (and sometimes these can physically overlap); such design elements shall be limited to the scope of the code being documented, that in turn depends on the chosen granularity, to this extent the drivers/subsystems granularity as per  [MAINTAINERs](https://github.com/torvalds/linux/blob/master/MAINTAINERS) file can be a starting point.

 \
**Possible elements impacting the expected behavior **of the API being documented that are in scope according to the above mentioned granularity:



* Input parameters: parameters passed to the API being documented;
* state variables: global and static data (variables or pointers);
* software dependencies: external SW APIs invoked by the code under analysis;
* Hardware dependencies: HW design elements directly impacting the behavior of the code in scope;
* Firmware dependencies: FW design elements that have an impact on the behavior of the API being documented (e.g. DTB or ACPI tables, or runtime services like SCMI and ACPI AML);
* Compile time configuration parameters: configuration parameters parsed when compiling the Kernel Image;
* Runtime configuration parameters (AKA calibration parameters): parameters that can be modified at runtime.

**Design elements impacted by the expected behavior** of the API being documented that are in scope according to the above mentioned granularity:



* API return values, including pointer addresses;
* Input pointers: pointers passed as input parameter to the API being documented;
* state variables: global and static data (variable or pointers); 
* Hardware design elements (e.g. HW registers);

**Testability considerations**: the impact of each of the documented “design elements impacting the expected behavior” shall be described in terms of effect on the “design element impacted by the expected behavior” and, in doing so, it is important to document allowed or not allowed ranges of values, corner cases and error conditions;  so that it will be possible to define a meaningful test plan according to different equivalence classes. 

**Scalability considerations**: the described expected behavior shall be limited to the scope of the code under analysis so for example the Software, Firmware and Hardware dependencies shall be described in terms of possible impact on the invoking code deferring further details to the respective documentation of these. The goal is to build a hierarchical documentation 

**Feasibility considerations**: Only the “meaningful” and “useful” expected behavior, and the design elements impacting it, shall be considered (e.g. a printk logging some info may be omitted). There are two reasons behind this point:



1. Having to document everything that the code does is more verbose than re-writing the code;
2. When the expected behavior is defined before implementing the code, the activity is done by an expert using a level of detail that is way more abstract than the code and only referring to what is important for him.

To this extent the Linux experts shall play a significant role in deciding the right level of detail, what to document and what to omit.


## Pilot Project

TBD

Following the ELISA workshop at NASA (on Dec 10-12 2024) it was decided to experiment and refine the requirements’ template on the Linux TRACING subsystem. The subsystem is unambiguously defined in the Linux Kernel MAINTAINERS file as follows:

 \
TRACING

M:	Steven Rostedt &lt;rostedt@goodmis.org>

M:	Masami Hiramatsu &lt;mhiramat@kernel.org>

R:	Mathieu Desnoyers &lt;mathieu.desnoyers@efficios.com>

L:	linux-kernel@vger.kernel.org

L:	linux-trace-kernel@vger.kernel.org

S:	Maintained

Q:	https://patchwork.kernel.org/project/linux-trace-kernel/list/

T:	git git://git.kernel.org/pub/scm/linux/kernel/git/trace/linux-trace.git

F:	Documentation/trace/*

F:	fs/tracefs/

F:	include/linux/trace*.h

F:	include/trace/

F:	kernel/trace/

F:	scripts/tracing/

F:	tools/testing/selftests/ftrace/

To coordinate requirements documentation contributions the following git repo can be used: \
https://github.com/elisa-tech/linux.git \
Practically speaking the above repo will be used to propose code changes that will turn into patchset submitted publicly to the Linux Trace mailing list. \


The first step of experimentation can be focused on the implementation of the SPDX-Req-Text and SPDX-Req-Note  fields, since these are the ones that will populate the source code and that will capture the semantic aspects that developers and maintainers are interested into. \
Once an initial set of requirement instances is successfully accepted upstream, we can focus on implementing the rest of the requirements’ fields in separate files, on implementing the scripts’ automation to monitor existing requirements against code changes and to alert for code contributions missing requirements and also on updating the Linux Kernel Documentation guidelines to adopt the requirement template and the new semantic improvements.


### Pilot Execution

The initial API set of our pilot project activities is represented by those APIs that are:



* Interfaces to user space applications (syscalls)
* Exported Symbols
* Any other relevant interface for other drivers/subsystems (that is not already defined as an exported symbol)
* Interrupt or Exception Handlers (if any)

The execution can be organized in different phases according to the following goals:



* Goal 1: define testable semantic specifications for an initial subset of APIs (e.g. 5 or 6 APIs) and get these accepted upstream
* Goal 2: define requirements with all required SPDX data in the sidecar files for the initial subset of APIs and the automation to raise flags when patches are proposed.
* Goal 3: complete the requirements’ definition for all the initial API set of the TRACING subsystem
* Goal 4: Introduce the Requirement Definition process in the Linux Kernel Documentation

Guidance from Linus on readability and hash length:



* [https://lwn.net/ml/all/CAHk-=wiwAz3UgPOWK3RdGXDnTRHcwVbxpuxCQt_0SoAJC-oGXQ@mail.gmail.com/](https://lwn.net/ml/all/CAHk-=wiwAz3UgPOWK3RdGXDnTRHcwVbxpuxCQt_0SoAJC-oGXQ@mail.gmail.com/)
* [https://lwn.net/Articles/1001526/](https://lwn.net/Articles/1001526/)

---------

Hi All,

If you are receiving this you probably expressed interest in the discussion[1]

on documenting the kernel design intent that spun out of the LPC 2024 Safe

Systems MC[2]. Please let me know if anyone else should be involved. Until we

can get a mailing list set up, I am happy to be the clearing house.

What follows will attempt to summarize the relevant points and draw a line

around some semblance of a path forward. Feedback, comments, participation,

etc. is strongly encouraged.

1. To the extent that one could call the Linux kernel "designed", this design

exists in the heads of developers, curated kernel documentation[3], commit

logs, mailing lists, conference proceedings, hallways, and a long tail of other

sources way too numerous to name.

2. If we define "software bug" as a "violation of human expectations", then it

follows that the intent of the designer is the metric by which we should be

evaluating the success or failure of an implementation.

Analyzing the above two points to any reasonable degree should make clear that

the Linux kernel has no consistent method for describing testable design intent

at the function or (where relevant) subfunction level. The reasonable

conclusion is that there is no way to know if any form of Linux kernel testing

is operating under the correct assumptions and, to the extent that it is, it is

impossible to say if it is comprehensive enough to cover the entire design.

We do a better job of describing design at higher levels of abstraction, but

that does not provide the necessary fidelity to express design intent well

enough to fully test it, nor does it support the collection and modification of

design intent in a way that can support tooling.

The LPC discussion came to a few important conclusions -

1. Testable expectations (design intent) need to ride along with the code at

the function or subfunction level.

2. We need tools to make this useful.

3. This cannot be a process step.

You can replace the phrases "testable expectation" and "design intent" with

"requirement" if that helps; they can all be used interchangeably in this

context. The important part is that the sum total of all requirements *is* the

design expression, and the implementation is considered valid when each

requirement is associated with a passing test.

It is important to emphasize the word "valid" here and avoid the use of the

word "correct". I believe validity can be considered a form of correctness

against invariants like requirements, but overall this work should not be

confused with formal verification[4]. The only promise is that the

implementation will accurately reflect the expressed design (and vice versa).

The intent here, and also my motivation for participating, is to create a

framework that will collect design intent (requirements), drive testing, and

support tool development. The benefit to the kernel development community

should be evident.

What may not be so evident is that this should create a much needed "bucket"

for OEMs in safety critical industries, who rely on requirements based design

as part of their certification processes, to engage with the Linux kernel

community to a far greater degree than they currently do.

This brings me to conclusion #3. Writing requirements is a specific skill and

requirements development is its own form of kernel maintenance. Kernel

developers should always feel free to propose requirements, but this should

never create any process steps in the patch submission process. Overall I would

expect requirements to consistently lag mainline development and only "catch

up" in stable releases.

And that is where conclusion #2 comes into play. Tools will need to be

developed to evaluate where requirements are missing and where requirements

need to be re-evaluated due to patching activity. Tools are also going to be

necessary to work through the myriad architecture and configuration induced

functional variations (e.g. memcpy with and without CONFIG_FORTIFY_SOURCE).

And finally conclusion #1 is that we need a machine readable requirements

template that allows us to apply requirements _directly_ to source code. This

is likely going to be a machine readable function header comment of some sort,

but the exact details are still up in the air. I have many ideas for a

template, but this email is getting too long and it is probably a good idea to

see where the conversation goes before jumping into details like that.

Going forward - The suggestion was made by Jonathan Corbet to start with SysFS

requirements, which seems like as good a place as any. I can also submit an RFC

documentation patch to the doc maintainers explaining all of this in detail

once we have something more substantive to show.

I also think we need a mailing list of some kind to coordinate discussion. In

order to keep the focus on the Linux kernel development community, I believe it

makes sense to request a list on [lists.linux.dev](http://lists.linux.dev/). I will submit a list request

here shortly unless there is a compelling reason not to.

Thank you,

..Ch:W..

[1] [https://www.youtube.com/watch?v=stqGiy85s_Y](https://www.youtube.com/watch?v=stqGiy85s_Y)

[2] [https://lpc.events/event/18/sessions/187/#20240920](https://lpc.events/event/18/sessions/187/#20240920)

[3] [https://docs.kernel.org/](https://docs.kernel.org/)

[4] [https://lpc.events/event/18/contributions/1726/](https://lpc.events/event/18/contributions/1726/)

