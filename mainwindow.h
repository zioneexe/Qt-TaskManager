#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTableWidget>
#include <QThread>
#include <QActionGroup>
#include <QString>
#include <QTimer>
#include <QMessageBox>
#include <string>
#include "windows.h"
#include "profile.h"
#include "profileapi.h"
#include "process.h"
#include <psapi.h>
#include <tchar.h>
#include <iostream>
#include <tlhelp32.h> // Include the Tool Help Library header

#pragma comment(lib, "kernel32.lib") // Link against kernel32.lib

QT_BEGIN_NAMESPACE
namespace Ui { class TaskManager; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    int findIndex(const std::vector<Process>& myVector, const Process& objToFind);
    QString formatCPUTime(ULONGLONG milliseconds);
    QString formatMemory(DWORD bytes);
    void checkProcesses();
    QString getProcessState(DWORD pid);
    bool isProcessRunning(DWORD pid);
    bool isProcessSuspended(DWORD pid);
    void setupTable();
    void createProcesses();
    void retrieveProcessData(DWORD pid, Process& process);
    bool suspendProcess(DWORD pid);
    bool resumeProcess(DWORD pid);
    bool endProcess(DWORD pid);
    bool setAffinity(DWORD pid, int coreIndex);
    bool setPriority(DWORD pid, DWORD priorityClass);
    void showContextMenu(const QPoint& pos);
    void refreshTable();
    void filterTable();

private slots:

    void on_buttonCreateProc_clicked();

    void on_buttonEndTask_clicked();

    void on_actionRunTask_triggered();

    void on_actionExit_triggered();

    void on_actionRefreshNow_triggered();

    void on_lineEditStart_textChanged(const QString &arg1);

    void on_lineEditEnd_textChanged(const QString &arg1);

    void on_lineEditStep_textChanged(const QString &arg1);

    void on_lineEditElemToSearc_textChanged(const QString &arg1);

private:
    Ui::TaskManager *ui;

    double rangeStartX;
    double rangeEndX;
    int rangeStepsCount;

    int elemToSearch;

    int columnCount = 17;

    QTableWidget* processTable;

    std::vector<Process> processesVector;

    std::vector<FILETIME> createTimeStartArr, exitTimeStartArr, kernelTimeStartArr, userTimeStartArr;

    QMenu* contextMenu;
    QAction* endAction;
    QAction* suspendAction;
    QAction* resumeAction;
    QMenu* setAffinityMenu;
    QMenu* setPriorityMenu;
    QActionGroup* affinityChoiceGroup;
    std::vector<QAction*> affinityCores;
    QAction* realtimePriorityClass;
    QAction* highPriorityClass;
    QAction* aboveNormalPriorityClass;
    QAction* normalPriorityClass;
    QAction* belowNormalPriorityClass;
    QAction* idlePriorityClass;
    QAction* processModeBackgroundBegin;
    QAction* processModeBackgroundEnd;

};
#endif // MAINWINDOW_H
