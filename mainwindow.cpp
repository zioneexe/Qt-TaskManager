#include "mainwindow.h"
#include "./ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::TaskManager)
{
    ui->setupUi(this);

    processTable = ui->tableWidget;
    setupTable();

    QTimer* refreshTimer = new QTimer(this);
    connect(refreshTimer, &QTimer::timeout, this, &MainWindow::refreshTable);
    refreshTimer->start(1000);

    QTimer* stateCheckTimer = new QTimer(this);
    connect(stateCheckTimer, &QTimer::timeout, this, &MainWindow::checkProcesses);
    stateCheckTimer->start(500);
}

MainWindow::~MainWindow()
{
    delete ui;
}

QString MainWindow::formatCPUTime(ULONGLONG milliseconds) {
    // Format the time in the "hh:mm:ss" format
    int seconds = static_cast<int>(milliseconds / 1000) % 60;
    int minutes = static_cast<int>(milliseconds / (1000 * 60)) % 60;
    int hours = static_cast<int>(milliseconds / (1000 * 60 * 60));

    return QString("%1:%2:%3").arg(hours, 2, 10, QChar('0'))
        .arg(minutes, 2, 10, QChar('0'))
        .arg(seconds, 2, 10, QChar('0'));
}

QString MainWindow::formatMemory(DWORD bytes) {
    QLocale locale(QLocale::English);
    QString formattedNumber = locale.toString(bytes / 1024);
    return formattedNumber + " K";
}

void MainWindow::checkProcesses()
{
    for (int i = 0; i < processesVector.size(); ++i)
    {
        QString currentState = getProcessState(processesVector[i].PID);

        if (currentState == "Running") processTable->item(i, 3)->setBackground(QBrush(Qt::green));
        else if (currentState == "Suspended") processTable->item(i, 3)->setBackground(QBrush(Qt::yellow));
        else if (currentState == "Terminated") processTable->item(i, 3)->setBackground(QBrush(Qt::red));
        else if (currentState == "ERROR") processTable->item(i, 3)->setBackground(QBrush(Qt::gray));

        processTable->item(i, 3)->setText(currentState);

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processesVector[i].PID);
        if (!hProcess) return;
        FILETIME createTimeEnd, exitTimeEnd, kernelTimeEnd, userTimeEnd;
        GetProcessTimes(hProcess, &createTimeEnd, &exitTimeEnd, &kernelTimeEnd, &userTimeEnd);
        ULONGLONG kernelTimeMs = ((ULONGLONG)kernelTimeEnd.dwHighDateTime << 32 | kernelTimeEnd.dwLowDateTime) -
                                 ((ULONGLONG)kernelTimeStartArr[i].dwHighDateTime << 32 | kernelTimeStartArr[i].dwLowDateTime);
        ULONGLONG userTimeMs = ((ULONGLONG)userTimeEnd.dwHighDateTime << 32 | userTimeEnd.dwLowDateTime) -
                               ((ULONGLONG)userTimeStartArr[i].dwHighDateTime << 32 | userTimeStartArr[i].dwLowDateTime);
        kernelTimeMs /= 10000; // Convert to milliseconds
        userTimeMs /= 10000; // Convert to milliseconds
        processesVector[i].CPUTime = kernelTimeMs + userTimeMs;

        CloseHandle(hProcess);
    }
}

bool MainWindow::isProcessRunning(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess != NULL) {
        DWORD exitCode;
        if (GetExitCodeProcess(hProcess, &exitCode)) {
            CloseHandle(hProcess);
            return (exitCode == STILL_ACTIVE);
        }
        CloseHandle(hProcess);
    }
    return false;
}

void MainWindow::setupTable()
{
    processTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    processTable->setSelectionMode(QAbstractItemView::SingleSelection);

    processTable->setColumnCount(columnCount);
    processTable->setRowCount(processesVector.size());
    processTable->setHorizontalHeaderLabels(QStringList() << "Name" << "PID" << "PPID" << "Status" << "CPU time"
                                                          << "User name" << "Base priority" << "Affinity" << "Handles" << "Threads"
                                                          << "Working set" << "Peak working set" << "Commit size"  << "Paged pool"
                                                          << "NP pool" << "Page faults" << "User objects"
                                            );
    processTable->verticalHeader()->setVisible(false);

    for (int row = 0; row < processesVector.size(); ++row) {
        for (int col = 0; col < columnCount; ++col) {
            QTableWidgetItem *item = new QTableWidgetItem("");
            processTable->setItem(row, col, item);
            item->setTextAlignment(Qt::AlignCenter);
        }
    }

    connect(processTable, &QTableWidget::customContextMenuRequested, this, &MainWindow::showContextMenu);
    processTable->setContextMenuPolicy(Qt::CustomContextMenu);

    connect(ui->lineEditFilter, &QLineEdit::textChanged, this, &MainWindow::filterTable);
}

void MainWindow::on_buttonCreateProc_clicked()
{
    createProcesses();
}


void MainWindow::on_buttonEndTask_clicked()
{
    int selectedRow = processTable->currentRow();

    if (selectedRow >= 0)
    {
        endProcess(processesVector[selectedRow].PID);
    } else
    {
        QMessageBox::information(this,"Error", "No tasks selected!.", QMessageBox::Ok);
    }
}

void MainWindow::createProcesses()
{
    STARTUPINFOA stInfo;
    PROCESS_INFORMATION pcInfo;

    if (ui->checkBoxTabulation->isChecked())
    {

        std::string cmd = "D:\\repos\\univ\\tabulation\\x64\\Debug\\tabulation.exe";
        cmd += " " + std::to_string(rangeStartX);
        cmd += " " + std::to_string(rangeEndX);
        cmd += " " + std::to_string(rangeStepsCount);

        ZeroMemory(&stInfo, sizeof(stInfo));
        ZeroMemory(&pcInfo, sizeof(pcInfo));

        int pid = CreateProcessA(NULL,
                                (LPSTR)cmd.c_str(),
                                NULL,
                                NULL,
                                0,
                                CREATE_NEW_CONSOLE,
                                NULL,
                                NULL,
                                &stInfo,
                                &pcInfo
                                );
        DWORD targetPIDTabulation = pcInfo.dwProcessId;
        Process processTabulation(pid);
        retrieveProcessData(targetPIDTabulation, processTabulation);
        processesVector.push_back(processTabulation);

        int i = processesVector.size();

        createTimeStartArr.resize(i);
        exitTimeStartArr.resize(i);
        kernelTimeStartArr.resize(i);
        userTimeStartArr.resize(i);

        GetProcessTimes(pcInfo.hProcess, &createTimeStartArr[i-1], &exitTimeStartArr[i-1], &kernelTimeStartArr[i-1], &userTimeStartArr[i-1]);

        CloseHandle(pcInfo.hProcess);
        CloseHandle(pcInfo.hThread);

    }

    if (ui->checkBoxWMP->isChecked())
    {
        std::string cmd = "C:\\Program Files (x86)\\Windows Media Player\\wmplayer.exe";

        ZeroMemory(&stInfo, sizeof(stInfo));
        ZeroMemory(&pcInfo, sizeof(pcInfo));


        int pid = CreateProcessA(NULL,
                                (LPSTR)cmd.c_str(),
                                NULL,
                                NULL,
                                0,
                                CREATE_NEW_CONSOLE,
                                NULL,
                                NULL,
                                &stInfo,
                                &pcInfo
                                );
        DWORD targetPIDWMP = pcInfo.dwProcessId;
        Process processWMP(pid);
        retrieveProcessData(targetPIDWMP, processWMP);
        processesVector.push_back(processWMP);

        int i = processesVector.size();

        createTimeStartArr.resize(i);
        exitTimeStartArr.resize(i);
        kernelTimeStartArr.resize(i);
        userTimeStartArr.resize(i);

        GetProcessTimes(pcInfo.hProcess, &createTimeStartArr[i-1], &exitTimeStartArr[i-1], &kernelTimeStartArr[i-1], &userTimeStartArr[i-1]);

        CloseHandle(pcInfo.hProcess);
        CloseHandle(pcInfo.hThread);
    }

    if (ui->checkBoxNetStat->isChecked())
    {
        std::string cmd = "cmd /c netstat -n 10";

        ZeroMemory(&stInfo, sizeof(stInfo));
        ZeroMemory(&pcInfo, sizeof(pcInfo));


        int pid = CreateProcessA(NULL,
                                (LPSTR)cmd.c_str(),
                                NULL,
                                NULL,
                                0,
                                CREATE_NEW_CONSOLE,
                                NULL,
                                NULL,
                                &stInfo,
                                &pcInfo
                                );
        DWORD targetPIDNetStat = pcInfo.dwProcessId;
        Process processNetStat(pid);
        retrieveProcessData(targetPIDNetStat, processNetStat);
        processesVector.push_back(processNetStat);

        int i = processesVector.size();

        createTimeStartArr.resize(i);
        exitTimeStartArr.resize(i);
        kernelTimeStartArr.resize(i);
        userTimeStartArr.resize(i);

        GetProcessTimes(pcInfo.hProcess, &createTimeStartArr[i-1], &exitTimeStartArr[i-1], &kernelTimeStartArr[i-1], &userTimeStartArr[i-1]);

        CloseHandle(pcInfo.hProcess);
        CloseHandle(pcInfo.hThread);
    }

    if (ui->checkBoxBinarySearch->isChecked())
    {
        std::string cmd = "D:\\repos\\univ\\binarysearch\\x64\\Debug\\binarysearch.exe";
        cmd += " " + std::to_string(elemToSearch);

        ZeroMemory(&stInfo, sizeof(stInfo));
        ZeroMemory(&pcInfo, sizeof(pcInfo));


        int pid = CreateProcessA(NULL,
                                (LPSTR)cmd.c_str(),
                                NULL,
                                NULL,
                                0,
                                CREATE_NEW_CONSOLE,
                                NULL,
                                NULL,
                                &stInfo,
                                &pcInfo
                                );
        DWORD targetPIDBinarySearch = pcInfo.dwProcessId;
        Process processBinarySearch(pid);
        retrieveProcessData(targetPIDBinarySearch, processBinarySearch);
        processesVector.push_back(processBinarySearch);

        int i = processesVector.size();

        createTimeStartArr.resize(i);
        exitTimeStartArr.resize(i);
        kernelTimeStartArr.resize(i);
        userTimeStartArr.resize(i);

        GetProcessTimes(pcInfo.hProcess, &createTimeStartArr[i-1], &exitTimeStartArr[i-1], &kernelTimeStartArr[i-1], &userTimeStartArr[i-1]);

        CloseHandle(pcInfo.hProcess);
        CloseHandle(pcInfo.hThread);
    }
    refreshTable();
}

bool MainWindow::suspendProcess(DWORD pid)
{
    // Open the process with THREAD_SUSPEND_RESUME access right
    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!hProcess) return false;

    // Get a list of all threads in the process
    HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnapshot != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 threadEntry;
        threadEntry.dwSize = sizeof(THREADENTRY32);

        if (Thread32First(hThreadSnapshot, &threadEntry))
        {
            do {
                if (threadEntry.th32OwnerProcessID == pid)
                {
                    // Suspend each thread in the target process
                    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadEntry.th32ThreadID);
                    if (hThread)
                    {
                        SuspendThread(hThread);
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hThreadSnapshot, &threadEntry));
        }
        CloseHandle(hThreadSnapshot);


        CloseHandle(hProcess);
        return true;
    } else {
        return false;
    }
}

bool MainWindow::resumeProcess(DWORD pid)
{
    // Open the process with THREAD_SUSPEND_RESUME access right
    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!hProcess) return false;

    // Get a list of all threads in the process
    HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnapshot != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 threadEntry;
        threadEntry.dwSize = sizeof(THREADENTRY32);

        if (Thread32First(hThreadSnapshot, &threadEntry))
        {
            do {
                if (threadEntry.th32OwnerProcessID == pid)
                {
                    // Resume each thread in the target process
                    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadEntry.th32ThreadID);
                    if (hThread)
                    {
                        ResumeThread(hThread);
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hThreadSnapshot, &threadEntry));
        }
        CloseHandle(hThreadSnapshot);
    }

    CloseHandle(hProcess);
    return true;
}

bool MainWindow::endProcess(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) return false;

    if (TerminateProcess(hProcess, 0))
    {
        WaitForSingleObject(hProcess, INFINITE);
        CloseHandle(hProcess);
        return true; // Process terminated successfully
    } else
    {
        // Error terminating the process
        CloseHandle(hProcess);
        return false;
    }
}

bool MainWindow::setAffinity(DWORD pid, int coreIndex)
{
    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
    if (!hProcess) return false;

    DWORD_PTR affinityMask = 0; // Initialize the affinity mask

    // Toggle the core's bit in the affinity mask
    affinityMask = 1 << coreIndex;

    if (SetProcessAffinityMask(hProcess, affinityMask))
    {
        CloseHandle(hProcess);
        return true;
    }
    else
    {
        return false;
        CloseHandle(hProcess);
    }
}

bool MainWindow::setPriority(DWORD pid, DWORD priorityClass)
{
    HANDLE hProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
    if (!hProcess) return false;

    if (SetPriorityClass(hProcess, priorityClass))
    {
        CloseHandle(hProcess);
        return true; // Priority set successfully
    } else
    {
        // Failed to set priority
        CloseHandle(hProcess);
        return false;
    }
}

void MainWindow::showContextMenu(const QPoint& pos)
{
    QTableWidgetItem* item = processTable->itemAt(pos);
    int row = processTable->row(item);

    if (row >= 0) {
        DWORD pid = processesVector[row].PID;

        contextMenu = new QMenu(processTable);
        endAction = new QAction("End task", processTable);
        suspendAction = new QAction("Suspend", processTable);
        resumeAction = new QAction("Resume", processTable);
        setAffinityMenu = new QMenu("Set affinity", contextMenu);
        setPriorityMenu = new QMenu("Change priority", contextMenu);
        affinityChoiceGroup = new QActionGroup(setAffinityMenu);
        realtimePriorityClass = new QAction("Realtime", setPriorityMenu);
        highPriorityClass = new QAction("High", setPriorityMenu);
        aboveNormalPriorityClass = new QAction("Above normal", setPriorityMenu);
        normalPriorityClass = new QAction("Normal", setPriorityMenu);
        belowNormalPriorityClass = new QAction("Below normal", setPriorityMenu);
        idlePriorityClass = new QAction("Idle", setPriorityMenu);
        processModeBackgroundBegin = new QAction("Background [BEGIN]", setPriorityMenu);
        processModeBackgroundEnd = new QAction("Background [END]", setPriorityMenu);

        contextMenu->addAction(endAction);
        contextMenu->addAction(suspendAction);
        contextMenu->addAction(resumeAction);
        contextMenu->addMenu(setAffinityMenu);
        contextMenu->addMenu(setPriorityMenu);

        for (int i = 0; i < 16; ++i)
        {
            QAction* affinityCore = new QAction(QString("Core %1").arg(i), this);
            affinityCores.push_back(affinityCore);
            affinityCore->setCheckable(true);

            affinityChoiceGroup->addAction(affinityCore);
            setAffinityMenu->addAction(affinityCore);

            connect(affinityCores[i], &QAction::triggered, this, [this, pid, i] {
                setAffinity(pid, i);
            });
        }

        setPriorityMenu->addAction(realtimePriorityClass);
        setPriorityMenu->addAction(highPriorityClass);
        setPriorityMenu->addAction(aboveNormalPriorityClass);
        setPriorityMenu->addAction(normalPriorityClass);
        setPriorityMenu->addAction(belowNormalPriorityClass);
        setPriorityMenu->addAction(idlePriorityClass);
        setPriorityMenu->addAction(processModeBackgroundBegin);
        setPriorityMenu->addAction(processModeBackgroundEnd);

        connect(endAction, &QAction::triggered, this, [this, pid] {
            endProcess(pid);
        });

        connect(suspendAction, &QAction::triggered, this, [this, pid] {
            suspendProcess(pid);
        });

        connect(resumeAction, &QAction::triggered, this, [this, pid] {
            resumeProcess(pid);
        });

        connect(realtimePriorityClass, &QAction::triggered, this, [this, pid] {
            setPriority(pid, REALTIME_PRIORITY_CLASS);
        });

        connect(highPriorityClass, &QAction::triggered, this, [this, pid] {
            setPriority(pid, HIGH_PRIORITY_CLASS);
        });

        connect(aboveNormalPriorityClass, &QAction::triggered, this, [this, pid] {
            setPriority(pid, ABOVE_NORMAL_PRIORITY_CLASS);
        });

        connect(normalPriorityClass, &QAction::triggered, this, [this, pid] {
            setPriority(pid, NORMAL_PRIORITY_CLASS);
        });

        connect(belowNormalPriorityClass, &QAction::triggered, this, [this, pid] {
            setPriority(pid, BELOW_NORMAL_PRIORITY_CLASS);
        });

        connect(idlePriorityClass, &QAction::triggered, this, [this, pid] {
            setPriority(pid, IDLE_PRIORITY_CLASS);
        });

        connect(processModeBackgroundBegin, &QAction::triggered, this, [this, pid] {
            setPriority(pid, PROCESS_MODE_BACKGROUND_BEGIN);
        });

        connect(processModeBackgroundEnd, &QAction::triggered, this, [this, pid] {
            setPriority(pid, PROCESS_MODE_BACKGROUND_END);
        });

        QAction* selectedItem = contextMenu->exec(QCursor::pos());
    }
}

void MainWindow::refreshTable()
{
    processTable->setHorizontalHeaderLabels(QStringList() << "Name" << "PID" << "PPID" << "Status" << "CPU time"
                                                          << "User name" << "Base priority" << "Affinity" << "Handles" << "Threads"
                                                          << "Working set" << "Peak working set" << "Commit size"  << "Paged pool"
                                                          << "NP pool" << "Page faults" << "User objects"
                                            );

    processTable->setRowCount(processesVector.size());
    for (int i = 0; i < processesVector.size(); ++i)
    {

        QString basePriorityString;
        switch (processesVector[i].basePriority)
        {
        case REALTIME_PRIORITY_CLASS:
            basePriorityString = "Realtime";
            break;
        case HIGH_PRIORITY_CLASS:
            basePriorityString = "High";
            break;
        case ABOVE_NORMAL_PRIORITY_CLASS:
            basePriorityString = "Above Normal";
            break;
        case NORMAL_PRIORITY_CLASS:
            basePriorityString = "Normal";
            break;
        case BELOW_NORMAL_PRIORITY_CLASS:
            basePriorityString = "Below Normal";
            break;
        case IDLE_PRIORITY_CLASS:
            basePriorityString = "Idle";
            break;
        case PROCESS_MODE_BACKGROUND_BEGIN:
            basePriorityString = "Background [BEGIN])";
            break;
        case PROCESS_MODE_BACKGROUND_END:
            basePriorityString = "Background [END]";
            break;
        default:
            basePriorityString = "N/A";
        }

        DWORD_PTR affinity = processesVector[i].affinity;
        QString affinityString;

        int coreStart = -1;
        int lastCore = -1;

        for (int core = 0; core < sizeof(DWORD_PTR) * 8; ++core) {
            if (affinity & (1ULL << core)) {
                if (coreStart == -1) {
                    // Start of a range
                    coreStart = core;
                }
                lastCore = core;
            } else if (coreStart != -1) {
                if (!affinityString.isEmpty()) {
                    affinityString += ", ";
                }
                if (coreStart == lastCore) {
                    affinityString += QString::number(coreStart + 1);
                } else {
                    affinityString += QString::number(coreStart + 1) + "-" + QString::number(lastCore + 1);
                }
                coreStart = -1;
            }
        }

        // Handle the case where the range ends at the last core
        if (coreStart != -1) {
            if (!affinityString.isEmpty()) {
                affinityString += ", ";
            }
            if (coreStart == lastCore) {
                affinityString += QString::number(coreStart + 1);
            } else {
                affinityString += QString::number(coreStart + 1) + "-" + QString::number(lastCore + 1);
            }
        }

        processTable->setItem(i, 0, new QTableWidgetItem(processesVector[i].Name));
        processTable->setItem(i, 1, new QTableWidgetItem(QString::number(processesVector[i].PID)));
        processTable->setItem(i, 2, new QTableWidgetItem(QString::number(processesVector[i].PPID)));
        processTable->setItem(i, 3, new QTableWidgetItem(processesVector[i].Status));
        processTable->setItem(i, 4, new QTableWidgetItem(formatCPUTime(processesVector[i].CPUTime)));
        processTable->setItem(i, 5, new QTableWidgetItem(processesVector[i].userName));
        processTable->setItem(i, 6, new QTableWidgetItem(basePriorityString));
        processTable->setItem(i, 7, new QTableWidgetItem(affinityString));
        processTable->setItem(i, 8, new QTableWidgetItem(QString::number(processesVector[i].handles)));
        processTable->setItem(i, 9, new QTableWidgetItem(QString::number(processesVector[i].threads)));
        processTable->setItem(i, 10, new QTableWidgetItem(formatMemory(processesVector[i].workingSet)));
        processTable->setItem(i, 11, new QTableWidgetItem(formatMemory(processesVector[i].peakWorkingSet)));
        processTable->setItem(i, 12, new QTableWidgetItem(formatMemory(processesVector[i].commitSize)));
        processTable->setItem(i, 13, new QTableWidgetItem(formatMemory(processesVector[i].pagedPool)));
        processTable->setItem(i, 14, new QTableWidgetItem(formatMemory(processesVector[i].NPpool)));
        processTable->setItem(i, 15, new QTableWidgetItem(QString::number(processesVector[i].pageFaults)));
        processTable->setItem(i, 16, new QTableWidgetItem(QString::number(processesVector[i].userObjects)));

        for (int j = 0; j < columnCount; ++j)
        {
            processTable->item(i, j)->setTextAlignment(Qt::AlignCenter);
        }

        if (!isProcessRunning(processesVector[i].PID))
        {
            QTimer timer;
            timer.setSingleShot(true);
            timer.setInterval(1000); // Delay for 1 second
            QEventLoop loop;
            connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
            timer.start();
            loop.exec(); // This blocks the program for one second

            processTable->removeRow(i);
            processesVector.erase(processesVector.begin() + i);
        }
    }
}

void MainWindow::filterTable()
{
    QString filterText = ui->lineEditFilter->text();
    QRegularExpression filterPattern(filterText, QRegularExpression::CaseInsensitiveOption);

    for (int row = 0; row < processTable->rowCount(); ++row) {
        QString processName = processTable->item(row, 0)->text(); // Assuming process names are in the first column
        if (filterPattern.match(processName).hasMatch()) {
            processTable->showRow(row);
        } else {
            processTable->hideRow(row);
        }
    }
}

bool MainWindow::isProcessSuspended(DWORD pid)
{
    HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (hThreadSnapshot == INVALID_HANDLE_VALUE)
    {
        // Handle error when creating the thread snapshot
        return false;
    }

    THREADENTRY32 threadEntry;
    threadEntry.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hThreadSnapshot, &threadEntry))
    {
        do
        {
            if (threadEntry.th32OwnerProcessID == pid)
            {
                // This is a thread of the target process, check if it's suspended
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadEntry.th32ThreadID);
                if (hThread != NULL)
                {
                    CONTEXT context;
                    context.ContextFlags = CONTEXT_ALL;

                    if (GetThreadContext(hThread, &context))
                    {
                        // Check if the EFlags register has the TF (trap flag) bit set, indicating a suspended thread
                        if (context.EFlags & 0x100)
                        {
                            // The thread is suspended
                            CloseHandle(hThread);
                            CloseHandle(hThreadSnapshot);
                            return true;
                        }
                    }

                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hThreadSnapshot, &threadEntry));
    }

    CloseHandle(hThreadSnapshot);

    // The process is not suspended or there was an error
    return false;
}


QString MainWindow::getProcessState(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess != NULL)
    {
        DWORD exitCode;
        if (GetExitCodeProcess(hProcess, &exitCode))
        {
            if (exitCode == STILL_ACTIVE)
            {
                if (isProcessSuspended(pid))
                {
                    return "Suspended";
                } else
                {
                    return "Running";
                }

            } else
            {
                return "Terminated";
            }
        }
    }
    return "ERROR";
}

void MainWindow::retrieveProcessData(DWORD pid, Process& process)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return;

    TCHAR szProcessName[MAX_PATH];
    if (GetModuleFileNameEx(hProcess, NULL, szProcessName, MAX_PATH)) {
        // Extract the file name from the full path
        const wchar_t* processName = _tcsrchr(szProcessName, '\\');
        process.Name = QString::fromWCharArray(processName + 1);
    }

    process.PID = pid;

    // Get Parent Process ID (PPID)
    HANDLE hProcessSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hProcessSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == process.PID) {
                process.PPID = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hProcessSnapshot, &pe32));
    }
    CloseHandle(hProcessSnapshot);

    process.basePriority = GetPriorityClass(hProcess);
    process.CPUTime = 0;

    // Get other information like handles, threads, working set, etc.
    PROCESS_MEMORY_COUNTERS_EX pmc;
    if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
        process.workingSet = pmc.WorkingSetSize;
        process.peakWorkingSet = pmc.PeakWorkingSetSize;
        process.commitSize = pmc.PrivateUsage;
        process.pagedPool = pmc.QuotaPagedPoolUsage;
        process.NPpool = pmc.QuotaNonPagedPoolUsage;
        process.pageFaults = pmc.PageFaultCount;
    }

    GetProcessHandleCount(hProcess, &process.handles);

    int threadCount = 0; // Initialize a counter for the number of threads.
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (snapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);

        if (Thread32First(snapshot, &te32)) {
            do {
                if (te32.th32OwnerProcessID == pid) {
                    ++threadCount; // Increment the thread count for each matching thread.
                }
            } while (Thread32Next(snapshot, &te32));

        } else {
            std::cerr << "Thread32First failed." << std::endl;
        }

        CloseHandle(snapshot);
    } else {
        std::cerr << "CreateToolhelp32Snapshot failed." << std::endl;
    }

    process.threads = threadCount;

    DWORD handleCount = 0;
    if (GetProcessHandleCount(hProcess, &handleCount))
    {
        process.handles = handleCount;
    } else
    {
        // Handle the error if you can't retrieve the handle count
        // You might want to log or display an error message here
        process.handles = 0; // Default to 0 handles
    }


    HANDLE hToken;
    DWORD tokenInfoSize = 0;

    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        // First, get the required tokenInfoSize
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &tokenInfoSize);

        if (tokenInfoSize > 0) {
            std::vector<BYTE> tokenInfoBuffer(tokenInfoSize);
            if (GetTokenInformation(hToken, TokenUser, tokenInfoBuffer.data(), tokenInfoSize, &tokenInfoSize)) {
                PTOKEN_USER tokenUser = reinterpret_cast<PTOKEN_USER>(tokenInfoBuffer.data());

                DWORD usernameSize = 0;
                DWORD domainSize = 0;
                SID_NAME_USE sidNameUse;
                LookupAccountSid(nullptr, tokenUser->User.Sid, nullptr, &usernameSize, nullptr, &domainSize, &sidNameUse);

                if (usernameSize > 0) {
                    char* usernameBuffer = static_cast<char*>(malloc(usernameSize));
                    if (LookupAccountSidA(nullptr, tokenUser->User.Sid, usernameBuffer, &usernameSize, nullptr, &domainSize, &sidNameUse)) {
                        // Assuming 'process' is a structure you're using to store the username.
                        process.userName = usernameBuffer; // No need for QString conversion.
                    }
                    free(usernameBuffer);
                }
            }
        }
        CloseHandle(hToken);
    }

    DWORD_PTR processAffinityMask;
    DWORD_PTR systemAffinityMask;

    if (GetProcessAffinityMask(hProcess, &processAffinityMask, &systemAffinityMask)) {
        process.affinity = processAffinityMask;
    }

    process.Status = getProcessState(pid);
    process.userObjects = GetGuiResources(hProcess, GR_USEROBJECTS);

    CloseHandle(hProcess);
}


void MainWindow::on_actionExit_triggered()
{
    QCoreApplication::quit();
}


void MainWindow::on_actionRefreshNow_triggered()
{
    refreshTable();
}


void MainWindow::on_lineEditStart_textChanged(const QString &arg1)
{
    rangeStartX = arg1.toDouble();
}


void MainWindow::on_lineEditEnd_textChanged(const QString &arg1)
{
    rangeEndX = arg1.toDouble();
}


void MainWindow::on_lineEditStep_textChanged(const QString &arg1)
{
    rangeStepsCount = arg1.toInt();
}


void MainWindow::on_lineEditElemToSearc_textChanged(const QString &arg1)
{
    elemToSearch = arg1.toDouble();
}
