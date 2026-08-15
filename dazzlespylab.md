DazzleSpyLab/
├── DazzleSpyLab.xcodeproj
│
├── DazzleSpyLab/
│   ├── App/
│   │   ├── DazzleSpyLabApp.swift
│   │   └── ContentView.swift
│   │
│   ├── Process/
│   │   ├── ProcessEnumerator.swift
│   │   ├── ProcessRecord.swift
│   │   ├── Architecture.swift
│   │   ├── RosettaDetector.swift
│   │   └── ProcessFlags.swift
│   │
│   ├── System/
│   │   ├── SystemProfiler.swift
│   │   ├── HardwareInfo.swift
│   │   ├── OSVersion.swift
│   │   ├── HostInfo.swift
│   │   └── NetworkInfo.swift
│   │
│   ├── Analysis/
│   │   ├── BinaryInspector.swift
│   │   ├── MachOParser.swift
│   │   ├── CodeSignatureInspector.swift
│   │   ├── EntitlementInspector.swift
│   │   └── SuspiciousProcessDetector.swift
│   │
│   ├── Commands/
│   │   ├── Command.swift
│   │   ├── CommandDispatcher.swift
│   │   ├── ListProcessesCommand.swift
│   │   ├── SystemInfoCommand.swift
│   │   └── InspectBinaryCommand.swift
│   │
│   ├── Simulation/
│   │   ├── SimulatedController.swift
│   │   ├── SimulatedMessage.swift
│   │   └── LocalCommandQueue.swift
│   │
│   ├── Logging/
│   │   ├── EventLogger.swift
│   │   ├── JSONLogger.swift
│   │   └── LogEvent.swift
│   │
│   ├── UI/
│   │   ├── DashboardView.swift
│   │   ├── ProcessListView.swift
│   │   ├── ProcessDetailView.swift
│   │   ├── SystemInfoView.swift
│   │   └── LogsView.swift
│   │
│   └── Utilities/
│       ├── Sysctl.swift
│       ├── FileUtils.swift
│       ├── Hex.swift
│       └── Extensions.swift
│
├── DazzleSpyLabTests/
│   ├── ArchitectureTests.swift
│   ├── MachOParserTests.swift
│   └── ProcessEnumeratorTests.swift
│
└── README.md
