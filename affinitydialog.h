#ifndef AFFINITYDIALOG_H
#define AFFINITYDIALOG_H

#include <QDialog>
#include <QVBoxLayout>
#include <QCheckBox>
#include <QPushButton>
#include "windows.h"

class AffinityDialog : public QDialog {
    Q_OBJECT

public:

    AffinityDialog(QWidget* parent = nullptr) : QDialog(parent) {
        globalAffinityMask = 0;

        setWindowTitle("Set CPU Affinity");

        QVBoxLayout* layout = new QVBoxLayout(this);

        // Create checkboxes for cores 0 to 15
        for (int core = 0; core < 16; ++core) {
            QCheckBox* coreCheckbox = new QCheckBox(QString("Core %1").arg(core), this);
            coreCheckboxes.push_back(coreCheckbox);
            layout->addWidget(coreCheckbox);
        }

        // Create an "Apply" button
        QPushButton* applyButton = new QPushButton("Apply", this);
        layout->addWidget(applyButton);

        // Connect the "Apply" button to the dialog's accept() slot
        connect(applyButton, &QPushButton::clicked, this, &AffinityDialog::accept);
    }

    // Method to get the selected affinity mask
    DWORD_PTR getAffinityMask() {
        DWORD_PTR affinityMask = 0;
        for (int core = 0; core < 16; ++core) {
            if (coreCheckboxes[core]->isChecked()) {
                affinityMask |= (1ULL << core); // Use 1ULL to shift a 64-bit mask
            }
        }
        globalAffinityMask = affinityMask; // Update the global affinity mask
        return affinityMask;
    }

    DWORD_PTR globalAffinityMask;
private:
    QVector<QCheckBox*> coreCheckboxes;
};

#endif // AFFINITYDIALOG_H
