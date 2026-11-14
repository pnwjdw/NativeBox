import QtQuick
import QtQuick.Window
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs
import QtQuick.Templates as Templates
import NativeBox.Controls 2.15

ApplicationWindow {
    id: window
    property real usableScreenWidth: Math.max(320, Screen.desktopAvailableWidth - 16)
    property real usableScreenHeight: Math.max(320, Screen.desktopAvailableHeight - 40)
    width: Math.min(1280, usableScreenWidth)
    height: Math.min(820, usableScreenHeight)
    minimumWidth: Math.min(960, usableScreenWidth)
    minimumHeight: Math.min(640, usableScreenHeight)
    visible: !validationMode
    title: "NativeBox Driverless"
    property int page: 0
    property color base: backend.dark ? "#11151d" : "#f1f4f9"
    property color panel: backend.dark ? "#1a202b" : "#ffffff"
    property color line: backend.dark ? "#2c3545" : "#dce2ec"
    property color ink: backend.dark ? "#edf2fa" : "#182238"
    property color muted: backend.dark ? "#94a3b8" : "#61718a"
    property color accent: "#63d8bd"
    property color accentInk: backend.dark ? accent : "#18604e"
    property color errorInk: backend.dark ? "#ec947e" : "#9e3528"
    property var profile: backend.selectedProfile()
    property string credentialProfile: ""
    property var pagesEn: ["Overview", "Sandboxes", "Applications", "Proxy manager", "Inspector", "Profiles", "Snapshots", "Settings", "About"]
    property var pagesRu: ["Обзор", "Песочницы", "Приложения", "Прокси", "Инспектор", "Профили", "Снимки", "Настройки", "О программе"]
    function t(ru, en) { return backend.language === "ru" ? ru : en }
    function queryEvents(next) {
        let args = {search:eventSearch.text,category:eventCategory.currentText,sort:eventSort.currentText,limit:200}
        if (next) args[eventSort.currentText === "descending" ? "before" : "after"] = backend.eventPage.nextAfter
        backend.perform("events.query",args)
    }
    function openApplicationLaunch(path, applicationArguments, directory) {
        launchDialog.sandbox = backend.selected
        launchExecutable.text = path
        if (typeof applicationArguments === "string") launchArguments.text = applicationArguments
        else if (applicationArguments && typeof applicationArguments.length === "number") {
            let values = []
            for (let index = 0; index < applicationArguments.length; ++index) values.push(applicationArguments[index])
            launchArguments.text = JSON.stringify(values)
        } else launchArguments.text = ""
        launchDirectory.text = directory || ""
        launchDialog.open()
    }
    function parseLaunchArguments(text) {
        if (text.indexOf("\u0000") >= 0) return {valid:false}
        if (text.trim().charAt(0) !== "[") return {valid:true,value:text}
        try {
            let value = JSON.parse(text)
            if (!Array.isArray(value) || value.some(arg => typeof arg !== "string" || arg.indexOf("\u0000") >= 0)) return {valid:false}
            return {valid:true,value:value}
        } catch (error) { return {valid:false} }
    }
    color: base
    font.family: "Segoe UI"
    font.pixelSize: 14
    palette.window: base
    palette.windowText: ink
    palette.base: panel
    palette.text: ink
    palette.button: panel
    palette.buttonText: ink
    palette.highlight: "#2f786c"
    palette.highlightedText: "white"
    palette.placeholderText: muted
    Connections { target: backend; function onChanged() { window.profile = backend.selectedProfile(); if (window.credentialProfile !== backend.selected) { proxyUsername.clear(); proxyPassword.clear(); window.credentialProfile = backend.selected } } }
    component StableScrollBar: NativeScrollBar {
        id: bar
        padding: 2
        hoverEnabled: true
        minimumSize: 0.08
        implicitWidth: 12
        implicitHeight: 12
        visible: policy !== ScrollBar.AlwaysOff
        opacity: size < 1 || policy === ScrollBar.AlwaysOn ? 1 : 0
        contentItem: Rectangle {
            implicitWidth: 8
            implicitHeight: 8
            radius: 4
            color: bar.pressed ? window.accent : (bar.hovered ? window.muted : window.line)
        }
        background: Rectangle { color: "transparent" }
        Accessible.name: orientation === Qt.Vertical ? window.t("Вертикальная прокрутка", "Vertical scroll") : window.t("Горизонтальная прокрутка", "Horizontal scroll")
    }
    component StableScrollView: Templates.ScrollView {
        id: viewport
        implicitWidth: contentWidth + leftPadding + rightPadding
        implicitHeight: contentHeight + topPadding + bottomPadding
        ScrollBar.horizontal: StableScrollBar {
            parent: viewport
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            anchors.leftMargin: viewport.leftPadding
            anchors.rightMargin: viewport.rightPadding
        }
        ScrollBar.vertical: StableScrollBar {
            parent: viewport
            anchors.top: parent.top
            anchors.bottom: parent.bottom
            anchors.left: viewport.mirrored ? parent.left : undefined
            anchors.right: viewport.mirrored ? undefined : parent.right
            anchors.topMargin: viewport.topPadding
            anchors.bottomMargin: viewport.bottomPadding
        }
    }
    component Action: Button {
        property bool primary: false
        implicitHeight: 38
        leftPadding: 16
        rightPadding: 16
        background: Rectangle {
            radius: 8
            color: parent.primary ? (parent.down ? "#45bba1" : window.accent) : (parent.hovered ? window.line : window.panel)
            border.width: parent.visualFocus ? 2 : 1
            border.color: parent.visualFocus ? window.accentInk : (parent.primary ? "transparent" : window.line)
            opacity: parent.enabled ? 1 : 0.4
        }
        contentItem: Text { textFormat: Text.PlainText;
            text: parent.text
            color: parent.primary ? "#09281f" : window.ink
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
            font: parent.font
            opacity: parent.enabled ? 1 : 0.4
        }
    }
    component Choice: ComboBox {
        id: choice
        delegate: ItemDelegate {
            required property int index
            width: choice.width
            text: choice.textAt(index)
            highlighted: choice.highlightedIndex === index
            contentItem: Text { textFormat: Text.PlainText;
                text: parent.text
                color: parent.highlighted ? "#09281f" : window.ink
                font: parent.font
                elide: Text.ElideRight
                verticalAlignment: Text.AlignVCenter
            }
            background: Rectangle { color: parent.highlighted ? window.accent : window.panel }
        }
    }
    function applyDialogLanguage(dialog) {
        var cancel = dialog.standardButton(Dialog.Cancel)
        if (cancel) {
            cancel.text = t("Отмена", "Cancel")
            cancel.objectName = "dialogCancel"
        }
    }
    component Card: Rectangle {
        color: window.panel
        border.color: window.line
        radius: 14
    }
    component Caption: Label { textFormat: Text.PlainText; color: window.muted; wrapMode: Text.Wrap }
    component Heading: Label { textFormat: Text.PlainText; color: window.ink; font.pixelSize: 23; font.weight: Font.DemiBold }
    component EmptyState: ColumnLayout {
        Layout.fillWidth: true
        Layout.fillHeight: true
        property string description
        Item { Layout.fillHeight: true }
        Label { textFormat: Text.PlainText; text: parent.description; color: window.muted; Layout.alignment: Qt.AlignHCenter; wrapMode: Text.Wrap; horizontalAlignment: Text.AlignHCenter; Layout.maximumWidth: 500 }
        Item { Layout.fillHeight: true }
    }
    RowLayout {
        anchors.fill: parent
        spacing: 0
        Rectangle {
            Layout.preferredWidth: 218
            Layout.minimumWidth: 218
            Layout.maximumWidth: 218
            Layout.fillHeight: true
            color: panel
            StableScrollView {
                id: navigationViewport
                objectName: "navigationViewport"
                anchors.fill: parent
                contentWidth: availableWidth
                contentHeight: Math.max(700, availableHeight)
                implicitWidth: 0; implicitHeight: 0
                clip: true
            ColumnLayout {
                x: 20; y: 20
                width: navigationViewport.availableWidth - 40
                height: navigationViewport.contentHeight - 40
                spacing: 10
                RowLayout {
                    Rectangle { width: 32; height: 32; radius: 9; color: accent; Label { textFormat: Text.PlainText; anchors.centerIn: parent; text: "N"; font.bold: true; color: "#09281f"; font.pixelSize: 21 } }
                    Label { textFormat: Text.PlainText; text: "NativeBox"; font.pixelSize: 21; font.weight: Font.DemiBold; color: ink }
                }
                Caption { text: "WINDOWS SANDBOX MANAGER"; font.pixelSize: 9; font.letterSpacing: 1; Layout.topMargin: 2; Layout.bottomMargin: 25 }
                Repeater {
                    model: backend.language === "ru" ? pagesRu : pagesEn
                    delegate: Button {
                        required property int index
                        required property string modelData
                        Layout.fillWidth: true
                        implicitHeight: 42
                        objectName: "nav-" + index
                        text: modelData
                        onClicked: window.page = index
                        Shortcut { sequence: "Alt+" + (index + 1); onActivated: window.page = index }
                        Accessible.description: window.t("Перейти: Alt+", "Navigate: Alt+") + (index + 1)
                        background: Rectangle { radius: 8; border.width: parent.visualFocus ? 2 : 0; border.color: window.accentInk; color: window.page === parent.index ? (backend.dark ? "#244139" : "#def4ed") : "transparent" }
                        contentItem: Text { textFormat: Text.PlainText; text: parent.text; color: window.page === parent.index ? (backend.dark ? accent : "#18604e") : muted; verticalAlignment: Text.AlignVCenter; leftPadding: 12; font.pixelSize: 14 }
                    }
                }
                Item { Layout.fillHeight: true }
                Rectangle { Layout.fillWidth: true; height: 1; color: line }
                Caption { text: t("Версия программы", "Application version"); font.pixelSize: 12 }
                Caption { text: backend.version + " · x64"; font.pixelSize: 11 }
            }
            }
        }
        Rectangle { Layout.fillHeight: true; width: 1; color: line }
        StableScrollView {
            id: workspaceViewport
            objectName: "workspaceViewport"
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.minimumWidth: 0
            Layout.minimumHeight: 0
            implicitWidth: 0; implicitHeight: 0
            contentWidth: Math.max(741, availableWidth)
            contentHeight: Math.max(640, availableHeight)
            clip: true
        ColumnLayout {
            objectName: "workspaceCanvas"
            x: 30; y: 30
            width: workspaceViewport.contentWidth - 60
            height: workspaceViewport.contentHeight - 60
            spacing: 18
            RowLayout {
                Heading { text: (backend.language === "ru" ? pagesRu : pagesEn)[window.page] }
                Item { Layout.fillWidth: true }
                Choice {
                    id: selector
                    Layout.preferredWidth: 230
                    model: backend.sandboxes
                    textRole: "name"
                    valueRole: "id"
                    onActivated: backend.selected = currentValue
                    enabled: !backend.busy
                    displayText: window.profile.name || t("Выберите песочницу", "Select a sandbox")
                }
                Action { text: t("Обновить", "Refresh"); enabled: !backend.busy; onClicked: backend.perform("refresh") }
            }
            Card {
                Layout.fillWidth: true
                implicitHeight: isolationBanner.implicitHeight + 28
                color: backend.dark ? "#30291d" : "#fff4df"
                border.color: backend.dark ? "#57472b" : "#ebcd96"
                Column {
                    id: isolationBanner
                    x: 14
                    y: 14
                    width: parent.width - 28
                    spacing: 8
                    Label { textFormat: Text.PlainText;
                        width: parent.width
                        text: t("Режим совместимости. Не предназначен для безопасного запуска вредоносных программ. USERMODE_REDIRECTED требует runtime; APP_PROFILE использует явно настроенный адаптер приложения.", "Compatibility mode. Not intended for safely running malicious programs. USERMODE_REDIRECTED requires the instrumentation runtime; APP_PROFILE uses an explicitly configured application adapter.")
                        color: backend.dark ? "#e7c990" : "#805419"
                        wrapMode: Text.Wrap
                        font.pixelSize: 12
                    }
                    Flow {
                        width: parent.width
                        spacing: 10
                        Repeater {
                            model: [{component:"Driverless",ready:true},{component:"Runtime",ready:!!backend.status.runtimeAvailable}]
                            delegate: Label { textFormat: Text.PlainText;
                                required property var modelData
                                property var names: ({driver:t("Драйвер", "Driver"), filesystem:t("Файлы", "Files"), registry:t("Реестр", "Registry"), process:t("Процессы", "Processes"), service:t("Служба", "Service"), network:t("Сеть", "Network"), dns:t("DNS", "DNS"), systemValidation:t("Системные испытания", "System validation")})
                                text: (names[modelData.component] || modelData.component) + ": " + (modelData.ready ? t("готов", "ready") : t("не готов", "not ready"))
                                color: modelData.ready ? accentInk : (backend.dark ? "#e7c990" : "#805419")
                                font.pixelSize: 11
                            }
                        }
                    }
                }
            }
            StackLayout {
                currentIndex: window.page
                Layout.fillWidth: true
                Layout.fillHeight: true
                ColumnLayout {
                    spacing: 20
                    RowLayout {
                        spacing: 16
                        Repeater {
                            model: [{name:t("Песочницы", "Sandboxes"),value:backend.sandboxes.length},{name:t("Активные процессы", "Active processes"),value:backend.status.activeProcesses || 0},{name:t("События в выборке", "Events in view"),value:backend.events.length}]
                            delegate: Card {
                                required property var modelData
                                Layout.fillWidth: true
                                implicitHeight: 118
                                ColumnLayout { anchors.fill: parent; anchors.margins: 20; Caption { text: modelData.name } Label { textFormat: Text.PlainText; text: modelData.value; color: ink; font.pixelSize: 34; font.weight: Font.DemiBold } }
                            }
                        }
                    }
                    Card {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        ColumnLayout {
                            anchors.fill: parent; anchors.margins: 22; spacing: 16
                            Heading { text: t("Рабочая область", "Workspace"); font.pixelSize: 18 }
                            Caption { text: t("Данные каждой среды хранятся отдельно. Изменения брокера не записываются в исходные файлы.", "Each environment has separate storage. Broker changes are kept apart from the original files.") }
                            Caption { text: backend.status.root || ""; font.family: "Consolas"; font.pixelSize: 12; Layout.fillWidth: true }
                            Action { text: t("Создать песочницу", "Create sandbox"); primary: true; enabled: !backend.busy; onClicked: createDialog.open() }
                            Item { Layout.fillHeight: true }
                            Caption { text: t("Активные приложения считаются по собственным Job. Измерения CPU/RAM/GPU в этой версии недоступны.", "Active applications are counted by owned jobs. CPU/RAM/GPU measurements are not available in this checkpoint.") }
                        }
                    }
                }
                ColumnLayout {
                    RowLayout {
                        Action { text: t("Создать", "Create"); primary: true; enabled: !backend.busy; onClicked: createDialog.open() }
                        Action { text: t("Клонировать", "Clone"); enabled: !!backend.selected && !backend.busy; onClicked: backend.perform("clone") }
                        Action { text: t("Запустить", "Launch"); enabled: !!backend.selected && !backend.busy; onClicked: { let apps = window.profile.applications || []; if (apps.length) window.openApplicationLaunch(apps[0].path,apps[0].arguments,apps[0].directory); else launchPicker.open() } }
                        Action { text: t("Остановить", "Stop"); enabled: !!backend.selected && !backend.busy; onClicked: backend.perform("stop") }
                        Action { objectName: "restartApplication"; text: t("Перезапустить", "Restart"); enabled: !!window.profile.canRestart && !backend.busy; onClicked: backend.perform("restart") }
                        Item { Layout.fillWidth: true }
                        Action { text: t("Удалить", "Delete"); enabled: !!backend.selected && !backend.busy; onClicked: { confirmDialog.operation = "delete"; confirmDialog.open() } }
                    }
                    ListView {
                        Layout.fillWidth: true; Layout.fillHeight: true; spacing: 10; clip: true
                        model: backend.sandboxes
                        delegate: Card {
                            required property var modelData
                            width: ListView.view.width; height: 92
                            border.color: backend.selected === modelData.id ? accent : line
                            RowLayout {
                                anchors.fill: parent; anchors.margins: 18
                                ColumnLayout { Layout.fillWidth: true; Label { textFormat: Text.PlainText; text: modelData.name; color: ink; font.pixelSize: 17; font.weight: Font.DemiBold } Caption { text: modelData.id; font.family: "Consolas"; font.pixelSize: 11 } }
                                Caption { text: (modelData.network || {}).mode || "offline" }
                                Action { text: t("Выбрать", "Select"); onClicked: backend.selected = modelData.id; enabled: !backend.busy }
                            }
                        }
                        Label { textFormat: Text.PlainText; anchors.centerIn: parent; visible: backend.sandboxes.length === 0; text: t("Создайте первую песочницу", "Create your first sandbox"); color: muted }
                        ScrollBar.vertical: StableScrollBar {}
                    }
                }
                ColumnLayout {
                    RowLayout { Action { text: t("Добавить EXE", "Add EXE"); primary: true; enabled: !!backend.selected && !backend.busy; onClicked: exePicker.open() } Caption { text: t("Избранные приложения выбранного профиля", "Favorites in the selected profile") } }
                    ListView {
                        Layout.fillWidth: true; Layout.fillHeight: true; clip: true; spacing: 10
                        model: window.profile.applications || []
                        delegate: Card {
                            required property var modelData
                            width: ListView.view.width; height: 80
                            RowLayout { anchors.fill: parent; anchors.margins: 18; Label { textFormat: Text.PlainText; text: modelData.path; color: ink; elide: Text.ElideMiddle; Layout.fillWidth: true } Action { text: t("Запустить", "Launch"); enabled: !backend.busy; onClicked: window.openApplicationLaunch(modelData.path,modelData.arguments,modelData.directory) } }
                        }
                        ScrollBar.vertical: StableScrollBar {}
                    }
                }
                StableScrollView {
                    Layout.fillWidth: true; Layout.fillHeight: true; contentWidth: availableWidth
                    ColumnLayout {
                        width: parent.width; spacing: 14
                        Caption { text: t("Direct использует обычную сеть. ManagedProxy обслуживает блокирующий TCP/IPv4 через runtime; DNS локальный. Это не сетевая граница безопасности.", "Direct uses the normal network. ManagedProxy routes blocking TCP/IPv4 through the runtime; DNS is local. This is not a network security boundary."); Layout.fillWidth: true }
                        Choice { id: proxyMode; model: ["direct","managed_proxy","offline","os_restricted_proxy"]; Layout.preferredWidth: 220; currentIndex: Math.max(0,model.indexOf((window.profile.network || {}).mode || "offline")) }
                        TextField { id: proxyHost; placeholderText: t("Адрес прокси", "Proxy host"); text: (window.profile.network || {}).host || ""; Layout.fillWidth: true }
                        SpinBox { id: proxyPort; from: 1; to: 65535; value: (window.profile.network || {}).port || 1080; editable: true }
                        Choice { id: strictProtocol; objectName: "strictProtocol"; model: ["socks5","http"]; currentIndex: Math.max(0,model.indexOf((window.profile.network || {}).protocol || "socks5")); visible: proxyMode.currentText === "managed_proxy" }
                        RowLayout {
                            Action { objectName: "saveProxy"; text: t("Сохранить маршрут", "Save route"); enabled: !!backend.selected && !backend.busy; primary: true; onClicked: { let p = Object.assign({},window.profile); p.network = {mode:proxyMode.currentText,host:proxyHost.text,port:proxyPort.value,protocol:strictProtocol.currentText,dns:"local",authenticated:proxyAuth.checked,timeoutMs:proxyTimeout.value}; backend.perform("profile.edit",{profile:p}) } }
                        }
                        RowLayout {
                            Switch { id: proxyAuth; objectName: "proxyAuth"; text: t("Авторизация", "Authentication"); checked: !!(window.profile.network || {}).authenticated }
                            Label { text: t("Таймаут, мс", "Timeout, ms"); color: ink }
                            SpinBox { id: proxyTimeout; from: 100; to: 30000; value: (window.profile.network || {}).timeoutMs || 5000; editable: true }
                        }
                        TextField { id: proxyUsername; objectName: "proxyUsername"; placeholderText: t("Имя пользователя", "Username"); Layout.fillWidth: true }
                        TextField { id: proxyPassword; objectName: "proxyPassword"; placeholderText: t("Пароль", "Password"); echoMode: TextInput.Password; inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText; Layout.fillWidth: true }
                        RowLayout {
                            Action { text: t("Сохранить учётные данные", "Save credentials"); enabled: !!backend.selected && !backend.busy && !!proxyUsername.text; onClicked: { backend.perform("credential.set",{username:proxyUsername.text,password:proxyPassword.text}); proxyPassword.clear() } }
                            Action { text: t("Удалить учётные данные", "Clear credentials"); enabled: !!backend.selected && !backend.busy; onClicked: { backend.perform("credential.clear"); proxyPassword.clear(); proxyUsername.clear() } }
                        }
                        Caption { text: t("Секреты хранятся отдельно в Windows Credential Manager и не входят в экспорт профиля. Изменять их можно после остановки приложения.", "Secrets are stored separately in Windows Credential Manager and excluded from profile exports. Stop the application before changing them."); Layout.fillWidth: true }
                        RowLayout {
                            TextField { id: proxyTestHost; objectName: "proxyTestHost"; placeholderText: t("IPv4 тестового назначения", "Test destination IPv4"); Layout.fillWidth: true }
                            SpinBox { id: proxyTestPort; from: 1; to: 65535; value: 443; editable: true }
                            Action { text: t("Проверить соединитель", "Test connector"); enabled: !!backend.selected && !!proxyTestHost.text && !backend.busy; onClicked: backend.perform("network.probe",{destination:proxyTestHost.text,port:proxyTestPort.value}) }
                        }
                        Caption { text: t("Проверка соединителя не доказывает совместимость сетевых API приложения с runtime. Запрос идёт только к указанному назначению через сохранённый прокси.", "A connector check does not qualify an application's network APIs under the runtime. The request uses the saved proxy and only the specified destination."); Layout.fillWidth: true }
                        Rectangle { Layout.fillWidth: true; height: 1; color: line }
                        Caption { text: t("UDP/QUIC, ConnectEx и неблокирующие сокеты не поддерживаются. Offline и OSRestrictedProxy отказывают в запуске. IPv6: EXCLUDED_IPV6_BY_OWNER.", "UDP/QUIC, ConnectEx and nonblocking sockets are unsupported. Offline and OSRestrictedProxy refuse launch. IPv6: EXCLUDED_IPV6_BY_OWNER."); Layout.fillWidth: true }
                    }
                }
                ColumnLayout {
                    id: inspectorPage
                    property bool showIdentityDetails: false
                    property bool showAuditDetails: false
                    TabBar {
                        id: inspectorTabs
                        objectName: "inspectorTabs"
                        Layout.fillWidth: true
                        TabButton { text: t("Файлы", "Files") }
                        TabButton { text: t("События и реестр", "Events and registry") }
                    }
                    ColumnLayout {
                        id: filesInspector
                        visible: inspectorTabs.currentIndex === 0
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        property string activeBox: backend.selected
                        function resetPath() {
                            if (!filePath) return
                            var selected = backend.selectedProfile()
                            filePath.text = ""
                        }
                        function browse(offset) {
                            if (backend.selected && !backend.busy)
                                backend.perform("file.list", {path:filePath.text,
                                                scope:"runtime",
                                                offset:offset,limit:128})
                        }
                        function entryPath(entry) {
                            return entry.path
                        }
                        onActiveBoxChanged: resetPath()
                        Component.onCompleted: resetPath()
                        RowLayout {
                            Choice {
                                id: fileScope
                                implicitContentWidthPolicy: ComboBox.WidestText
                                model: [t("Частные данные", "Private data")]
                                onActivated: { filesInspector.resetPath(); filesInspector.browse(0) }
                            }
                            TextField {
                                id: filePath
                                Layout.fillWidth: true
                                placeholderText: t("Относительный путь", "Relative path")
                                onAccepted: filesInspector.browse(0)
                            }
                            Action { text: t("Показать", "Browse"); enabled: !!backend.selected && !backend.busy; onClicked: filesInspector.browse(0) }
                        }
                        Caption {
                            Layout.fillWidth: true
                            text: backend.filePage.live ? t("Текущее состояние работающей песочницы.", "Current state of the running sandbox.")
                                                        : t("Просмотр файлов и метаданных выбранной песочницы.", "Browse files and metadata of the selected sandbox.")
                        }
                        ListView {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            clip: true
                            spacing: 4
                            model: backend.filePage.entries || []
                            delegate: Card {
                                required property var modelData
                                width: ListView.view.width
                                height: 62
                                RowLayout {
                                    anchors.fill: parent
                                    anchors.margins: 8
                                    Label { textFormat: Text.PlainText; text: modelData.directory ? "▸" : "·"; color: accentInk }
                                    Label { textFormat: Text.PlainText; text: modelData.name; elide: Text.ElideMiddle; Layout.fillWidth: true }
                                    Caption { text: modelData.directory ? t("Папка", "Folder") : String(modelData.size) + t(" байт", " bytes") }
                                    Caption { visible: !!modelData.overlay; text: t("Изменён", "Modified"); color: accentInk }
                                    Action {
                                        text: t("Открыть", "Open")
                                        visible: !!modelData.directory
                                        enabled: !backend.busy
                                        onClicked: { filePath.text = filesInspector.entryPath(modelData); filesInspector.browse(0) }
                                    }
                                    Action {
                                        text: t("Сведения", "Details")
                                        enabled: !backend.busy
                                        onClicked: backend.perform("file.stat", {path:filesInspector.entryPath(modelData), scope:"runtime"})
                                    }
                                }
                            }
                            ScrollBar.vertical: StableScrollBar {}
                        }
                        RowLayout {
                            Caption { text: String((backend.filePage.entries || []).length) + " / " + String(backend.filePage.total === undefined ? (backend.filePage.entries || []).length : backend.filePage.total); Layout.fillWidth: true }
                            Action { text: t("С начала", "First page"); enabled: !!backend.selected && !backend.busy; onClicked: filesInspector.browse(0) }
                            Action {
                                text: t("Далее", "Next page")
                                enabled: !!backend.filePage.hasMore && !backend.busy
                                onClicked: { var offset = backend.filePage.nextOffset; filePath.text = backend.filePage.path; filesInspector.browse(offset) }
                            }
                        }
                        StableScrollView {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 130
                            TextArea { readOnly: true; selectByMouse: true; text: backend.pretty(backend.fileMetadata); font.family: "Consolas"; font.pixelSize: 11 }
                        }
                    }
                    ColumnLayout {
                        visible: inspectorTabs.currentIndex === 1
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        RowLayout {
                            TextField { id: eventSearch; objectName: "eventSearch"; placeholderText: t("Поиск событий", "Search events"); Layout.fillWidth: true; onAccepted: window.queryEvents(false) }
                            Choice { id: eventCategory; model: ["", "file", "registry", "process", "network", "wmi", "syscall", "telemetry", "broker"]; Layout.preferredWidth: 125 }
                            Choice { id: eventSort; model: ["ascending", "descending"]; Layout.preferredWidth: 130 }
                            Action { text: t("Найти", "Search"); enabled: !backend.busy; onClicked: window.queryEvents(false) }
                            Action { text: "JSON"; enabled: !backend.busy; onClicked: { exportPicker.kind = "events"; exportPicker.format = "json"; exportPicker.open() } }
                            Action { text: "CSV"; enabled: !backend.busy; onClicked: { exportPicker.kind = "events"; exportPicker.format = "csv"; exportPicker.open() } }
                        }
                        RowLayout {
                            Action { text: t("Первая страница", "First page"); enabled: !backend.busy; onClicked: window.queryEvents(false) }
                            Action { text: t("Следующая страница", "Next page"); enabled: !!backend.eventPage.hasMore && !backend.busy; onClicked: window.queryEvents(true) }
                            Caption { text: t("Таблица и JSON/CSV — до 50000 событий. Полный JSONL выгружает все сохранённые журналы песочницы без лимита числа событий; фильтры таблицы к нему не применяются.", "Table and JSON/CSV: up to 50000 events. Full JSONL exports all archived sandbox logs without an event-count limit; table filters do not apply."); Layout.fillWidth: true }
                        }
                        Caption { visible: !!backend.telemetry.incompleteChunks || !!backend.telemetry.limitMarkers || !!backend.telemetry.moreDataPending; text: t("Неполных фрагментов: ", "Incomplete chunks: ") + String(backend.telemetry.incompleteChunks || 0) + t("; лимитов старых журналов: ", "; legacy log limits: ") + String(backend.telemetry.limitMarkers || 0) + (!!backend.telemetry.moreDataPending ? t("; импорт продолжается", "; import pending") : ""); color: errorInk; Layout.fillWidth: true }
                        RowLayout {
                            Action { text: t("Включить системный журнал", "Start system audit"); enabled: !backend.busy; onClicked: backend.perform("audit.enable") }
                            Action { text: t("Остановить журнал ETW", "Stop ETW audit"); enabled: !backend.busy && !!(backend.telemetry.systemAudit || {}).connected; onClicked: backend.perform("audit.disable") }
                        }
                        RowLayout {
                            Action { text: t("Полный JSONL", "Full JSONL"); enabled: !!backend.selected && !backend.busy; onClicked: { exportPicker.kind = "events"; exportPicker.format = "jsonl"; exportPicker.open() } }
                            Action { text: t("Файлы журнала", "Runtime log files"); enabled: !!backend.telemetry.rawLogUrl; onClicked: Qt.openUrlExternally(backend.telemetry.rawLogUrl) }
                            Action { text: t("Файлы ETW", "ETW files"); enabled: !!backend.telemetry.auditLogUrl; onClicked: Qt.openUrlExternally(backend.telemetry.auditLogUrl) }
                        }
                        Caption { text: t("Журнал Windows: ", "Windows audit: ") + ((backend.telemetry.systemAudit || {}).active ? t("включён", "on") : t("выключен", "off")) + t(" · Источники: ", " · Providers: ") + ((backend.telemetry.systemAudit || {}).allRequestedProvidersReady ? t("готовы", "ready") : t("недоступны или не запущены", "unavailable or not started")) + t(" · Системные вызовы: ", " · System calls: ") + ((backend.telemetry.systemAudit || {}).systemCallsReady ? t("готовы", "ready") : t("не запущены", "not started")) + " · " + String((backend.telemetry.systemAudit || {}).error || ""); Layout.fillWidth: true }
                        Caption { text: t("Потеряно Windows / очередью: ", "Lost by Windows / queue: ") + String((backend.telemetry.systemAudit || {}).eventsLost || 0) + " / " + String((backend.telemetry.systemAudit || {}).queueDropped || 0) + t("; неполное декодирование: ", "; partial decoding: ") + String((backend.telemetry.systemAudit || {}).decodeErrors || 0); color: Number((backend.telemetry.systemAudit || {}).eventsLost || 0) + Number((backend.telemetry.systemAudit || {}).queueDropped || 0) > 0 ? errorInk : muted; Layout.fillWidth: true }
                        Caption {
                            property var audit: backend.telemetry.systemAudit || {}
                            property real gaps: Number(audit.realtimeLostEventNotifications || 0) + Number(audit.realtimeLostBufferNotifications || 0) + Number(audit.realtimeLostFileNotifications || 0)
                            text: t("Уведомлений Windows о пропусках: ", "Windows gap notifications: ") + String(gaps) + (audit.liveLossCountersProvisional ? t(" · Счётчики предварительные до остановки трассировки", " · Counters are provisional until tracing stops") : "")
                            color: gaps > 0 ? errorInk : muted
                            Layout.fillWidth: true
                        }
                        Action { text: t("Состояние источников", "Provider status"); onClicked: inspectorPage.showAuditDetails = !inspectorPage.showAuditDetails }
                        StableScrollView {
                            Layout.fillWidth: true; Layout.preferredHeight: 140
                            visible: inspectorPage.showAuditDetails
                            TextArea { readOnly: true; selectByMouse: true; wrapMode: TextEdit.Wrap; text: backend.pretty(backend.telemetry.systemAudit || {}); font.family: "Consolas"; font.pixelSize: 11 }
                        }
                        Caption { text: t("Для ETW Windows запрашивает права администратора. Приложения запускаются с обычными правами. Исходные журналы JSONL сохраняются отдельно; таблица показывает последние 50000 событий. Системные вызовы: вход/адрес и выход/статус; аргументы Windows не предоставляет.", "Windows requests administrator rights for ETW. Targets keep ordinary privileges. Raw JSONL logs are retained separately; the table keeps the latest 50000 events. System calls expose entry/address and exit/status; Windows does not provide arguments."); Layout.fillWidth: true }
                        Caption {
                            Layout.fillWidth: true
                            visible: !!backend.registryAudit.mappingDigest
                            text: backend.registryAudit.nativeEvidenceAvailable
                                  ? t("Рисков старой схемы имён: ", "Legacy name folding risks: ") + backend.registryAudit.legacyCollisionGroups
                                    + t(". Несовпадений метаданных: ", ". Metadata mismatches: ") + backend.registryAudit.metadataMismatchRows
                                    + t(". Удалений без исходных имён: ", ". Deletions without original name evidence: ") + backend.registryAudit.deletionMarkersWithoutNameEvidence
                                  : t("Проверены только метаданные. Частный реестр не проверен.", "Only metadata was inspected. The private registry was not inspected.")
                        }
                        Label { textFormat: Text.PlainText;
                            visible: !!backend.registryAudit.mappingDrift
                            text: t("Таблица имён Windows изменилась. Операции реестра заблокированы до проверенной миграции.", "The Windows name mapping changed. Registry operations are blocked until an audited migration.")
                            wrapMode: Text.WordWrap
                            Layout.fillWidth: true
                        }
                        Action {
                            visible: !!backend.registryAudit.mappingDigest
                            text: t("Подробности проверки", "Audit details")
                            onClicked: inspectorPage.showIdentityDetails = !inspectorPage.showIdentityDetails
                        }
                        StableScrollView {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 130
                            visible: inspectorPage.showIdentityDetails && !!backend.registryAudit.mappingDigest
                            TextArea { readOnly: true; wrapMode: TextEdit.Wrap; text: backend.pretty(backend.registryAudit.issues || []); font.family: "Consolas"; font.pixelSize: 11 }
                        }
                        Caption { text: t("События брокера и покрытых Win32-вызовов runtime. Наблюдение неполное; отсутствие события не доказывает отсутствие операции. Источников: ", "Broker and covered runtime Win32 events. Observation is incomplete; missing events do not prove absence of operations. Sources: ") + String(backend.telemetry.sources || 0) + "; " + String(backend.telemetry.status || "unknown") + "; " + t("отклонено: ", "rejected: ") + String(backend.telemetry.rejected || 0); Layout.fillWidth: true }
                        ListView {
                            Layout.fillWidth: true; Layout.fillHeight: true; clip: true; spacing: 5; model: backend.events
                            delegate: Card {
                                required property var modelData
                                property bool matches: !eventSearch.text || JSON.stringify(modelData).toLowerCase().indexOf(eventSearch.text.toLowerCase()) >= 0
                                visible: matches; width: ListView.view.width; height: matches ? 74 : 0
                                ColumnLayout { anchors.fill: parent; anchors.margins: 12; RowLayout { Caption { text: (modelData.details || {}).timeUtc || modelData.time; font.family: "Consolas"; font.pixelSize: 11 } Label { textFormat: Text.PlainText; objectName: "eventKind"; text: modelData.category + " / " + modelData.action; color: accentInk; Layout.fillWidth: true } } Caption { text: JSON.stringify(modelData.details); elide: Text.ElideRight; Layout.fillWidth: true } }
                            }
                            ScrollBar.vertical: StableScrollBar {}
                        }
                    }
                }
                ColumnLayout {
                    RowLayout {
                        Action { objectName: "configureProfile"; text: t("Режим и области", "Mode and scopes"); primary: true; enabled: !!backend.selected && !backend.busy; onClicked: scopeDialog.open() }
                        Action { objectName: "editProfileAction"; text: t("Изменить JSON", "Edit JSON"); primary: true; enabled: !!backend.selected && !backend.busy; onClicked: { profileEditor.text = backend.pretty(window.profile); editDialog.open() } }
                        Action { text: t("Импорт", "Import"); enabled: !backend.busy; onClicked: importPicker.open() }
                        Action { text: t("Экспорт", "Export"); enabled: !!backend.selected && !backend.busy; onClicked: { exportPicker.kind = "profile"; exportPicker.open() } }
                    }
                    Caption { text: t("Режим, адаптер и охват операций задаются в профиле. APP_PROFILE не перехватывает произвольные файлы и реестр. Ограничениями устройств управляет Windows.", "The profile declares execution mode, adapter and coverage. APP_PROFILE does not intercept arbitrary files or registry calls. Windows controls device access."); Layout.fillWidth: true }
                    StableScrollView { Layout.fillWidth: true; Layout.fillHeight: true; TextArea { objectName: "profilePreview"; text: backend.pretty(window.profile); readOnly: true; font.family: "Consolas"; font.pixelSize: 12; wrapMode: TextEdit.Wrap; color: ink } }
                }
                ColumnLayout {
                    RowLayout {
                        Action { text: t("Создать снимок", "Create snapshot"); primary: true; enabled: !!backend.selected && !backend.busy; onClicked: backend.perform("snapshot.create") }
                        Action { text: t("Очистить данные", "Reset data"); enabled: !!backend.selected && !backend.busy; onClicked: { confirmDialog.operation = "reset"; confirmDialog.open() } }
                    }
                    Caption { text: t("Снимки создаются при остановленных приложениях. При восстановлении проверяются манифест и SHA-256 файлов.", "Snapshots require stopped applications. Restore checks the manifest and file SHA-256 digests."); Layout.fillWidth: true }
                    ListView {
                        Layout.fillWidth: true; Layout.fillHeight: true; model: backend.snapshots; spacing: 10; clip: true
                        delegate: Card {
                            required property var modelData
                            width: ListView.view.width; height: 82
                            RowLayout { anchors.fill: parent; anchors.margins: 16; ColumnLayout { Layout.fillWidth: true; Label { textFormat: Text.PlainText; text: modelData.created; color: ink } Caption { text: modelData.id; font.pixelSize: 11 } } Action { text: t("Восстановить", "Restore"); enabled: !backend.busy; onClicked: { confirmDialog.operation = "snapshot.restore"; confirmDialog.snapshot = modelData.id; confirmDialog.open() } } Action { text: t("Удалить", "Delete"); enabled: !backend.busy; onClicked: backend.perform("snapshot.delete",{snapshot:modelData.id}) } }
                        }
                        ScrollBar.vertical: StableScrollBar {}
                    }
                }
                ColumnLayout {
                    spacing: 18
                    Label { textFormat: Text.PlainText; text: t("Внешний вид", "Appearance"); color: ink; font.pixelSize: 18 }
                    Switch { objectName: "darkThemeSwitch"; text: t("Тёмная тема", "Dark theme"); checked: backend.dark; onToggled: backend.dark = checked }
                    Choice { objectName: "languageChoice"; model: ["Русский", "English"]; currentIndex: backend.language === "ru" ? 0 : 1; onActivated: backend.language = currentIndex === 0 ? "ru" : "en" }
                    Caption { text: t("Путь хранилища задаётся параметром --root. Автозапуск и автоматическая установка обновлений не включены.", "The --root argument selects storage. Autostart and automatic update installation are not enabled."); Layout.fillWidth: true }
                    Action { text: t("Диагностика устройств недоступна", "Device diagnostics unavailable"); enabled: false; onClicked: backend.perform("devices") }
                    StableScrollView {
                        objectName: "deviceReportView"
                        clip: true
                        visible: Object.keys(backend.devices).length > 0
                        Layout.fillWidth: true; Layout.fillHeight: true
                        contentWidth: availableWidth
                        TextArea {
                            objectName: "deviceReport"
                            text: backend.pretty(backend.devices)
                            readOnly: true; selectByMouse: true
                            font.family: "Consolas"; font.pixelSize: 12
                            wrapMode: TextEdit.Wrap; color: ink
                        }
                    }
                    Item { Layout.fillHeight: true; visible: Object.keys(backend.devices).length === 0 }

                }
                ColumnLayout {
                    Heading { text: "NativeBox " + backend.version + (backend.buildScope === "DEVELOPMENT_ONLY" ? " DEVELOPMENT_ONLY" : "") }
                    Caption { text: t("Сборка: ", "Build: ") + backend.buildIdentity + " · C++20 · Qt 6.8.3 · SQLite · Windows x64 · runtime x64/x86"; Layout.fillWidth: true }
                    Caption { text: t("Менеджер профилей приложений Windows без дополнительных драйверов: USERMODE_REDIRECTED перенаправляет выбранные папки, ключи реестра и сетевые соединения обычных программ, APP_PROFILE использует собственные параметры каталога данных программы. Режим совместимости: не является границей безопасности для вредоносных программ. IPv6 в этой версии не проверялся.", "Windows application profile manager without additional drivers: USERMODE_REDIRECTED redirects selected folders, registry keys and network connections of ordinary programs, APP_PROFILE uses the program's own data-directory parameters. Compatibility mode: not a security boundary for malicious programs. IPv6 was not qualified in this version."); Layout.fillWidth: true }
                    Caption { text: t("NativeBox распространяется по лицензии MIT, Copyright (c) 2026 yorenov / akegga. Лицензии и исходные материалы сторонних компонентов находятся в папке licenses. Диагностика не отправляется автоматически.", "NativeBox is distributed under the MIT License, Copyright (c) 2026 yorenov / akegga. Third-party licenses and corresponding sources are in the licenses directory. Diagnostics are not uploaded automatically."); Layout.fillWidth: true }
                    Item { Layout.fillHeight: true }
                }
            }
            ProgressBar { Layout.fillWidth: true; indeterminate: true; visible: backend.busy; implicitHeight: 3 }
            Label { textFormat: Text.PlainText; objectName: "operationStatus"; Layout.fillWidth: true; text: backend.message; color: backend.failed ? errorInk : muted; visible: !!text; wrapMode: Text.Wrap; maximumLineCount: 5; elide: Text.ElideRight; font.pixelSize: 12 }
        }
        }
    }
    Dialog {
        id: createDialog
        objectName: "createDialog"
        anchors.centerIn: parent
        title: window.t("Новая песочница", "New sandbox")
        modal: true
        focus: true
        standardButtons: Dialog.Ok | Dialog.Cancel
        onOpened: { window.applyDialogLanguage(createDialog); boxName.forceActiveFocus() }
        onAccepted: { backend.perform("create",{profile:{name:boxName.text,network:{mode:"direct"},readRoots:[],audit:{required:true}}}); boxName.clear() }
        ColumnLayout { width: 380; TextField { id: boxName; objectName: "sandboxName"; placeholderText: window.t("Название", "Name"); Layout.fillWidth: true; onAccepted: if (text.trim().length) createDialog.accept() } Caption { text: window.t("По умолчанию выбраны USERMODE_REDIRECTED и Direct. Без runtime запуск будет отклонён. Это не граница доступа к файлам Windows.", "Defaults are USERMODE_REDIRECTED and Direct. Launch is refused without a runtime. This is not an access boundary for Windows files."); Layout.fillWidth: true } }
    }
    Dialog {
        id: confirmDialog
        objectName: "confirmDialog"
        width: Math.min(460, window.width - 48)
        contentWidth: Math.max(0, width - leftPadding - rightPadding)
        property string operation
        property string snapshot
        anchors.centerIn: parent
        title: window.t("Подтверждение изменения данных", "Confirm data change")
        modal: true
        focus: true
        standardButtons: Dialog.Ok | Dialog.Cancel
        onOpened: { window.applyDialogLanguage(confirmDialog); standardButton(Dialog.Cancel).forceActiveFocus() }
        Label { textFormat: Text.PlainText; text: window.t("Операция изменит данные выбранной песочницы: ", "This changes selected sandbox data: ") + confirmDialog.operation; color: ink; wrapMode: Text.Wrap; width: confirmDialog.availableWidth }
        onAccepted: backend.perform(operation,{snapshot:snapshot})
    }
    Dialog {
        id: editDialog
        objectName: "profileDialog"
        anchors.centerIn: parent
        width: Math.min(780,window.width - 80)
        height: Math.min(640,window.height - 80)
        title: window.t("Профиль JSON", "Profile JSON")
        modal: true
        focus: true
        standardButtons: Dialog.Ok | Dialog.Cancel
        onOpened: { window.applyDialogLanguage(editDialog); profileEditor.forceActiveFocus() }
        onAccepted: backend.perform("profile.editJson",{json:profileEditor.text})
        StableScrollView {
            anchors.fill: parent
            TextArea {
                id: profileEditor
                objectName: "profileEditor"
                textFormat: TextEdit.PlainText
                font.family: "Consolas"; font.pixelSize: 12
                wrapMode: TextEdit.Wrap; selectByMouse: true
                Keys.onTabPressed: (event) => { editDialog.standardButton(Dialog.Ok).forceActiveFocus(Qt.TabFocusReason); event.accepted = true }
                Keys.onBacktabPressed: (event) => { editDialog.standardButton(Dialog.Cancel).forceActiveFocus(Qt.BacktabFocusReason); event.accepted = true }
            }
        }
    }
    Dialog {
        id: launchDialog
        objectName: "launchDialog"
        property string sandbox
        property var parsedArguments: window.parseLaunchArguments(launchArguments.text)
        anchors.centerIn: parent
        width: Math.min(680,window.width - 48)
        modal: true
        focus: true
        title: window.t("Запуск приложения", "Launch application")
        onOpened: launchArguments.forceActiveFocus()
        onAccepted: {
            if (sandbox !== backend.selected || backend.busy || !parsedArguments.valid) return
            let request = {executable:launchExecutable.text,arguments:parsedArguments.value}
            if (launchDirectory.text.trim()) request.directory = launchDirectory.text
            backend.perform("launch",request)
        }
        ColumnLayout {
            width: launchDialog.availableWidth
            Caption { text: window.t("Приложение", "Application"); Layout.fillWidth: true }
            TextField { id: launchExecutable; objectName: "launchExecutable"; readOnly: true; selectByMouse: true; Layout.fillWidth: true }
            Caption { text: window.t("Аргументы: строка Windows или JSON-массив строк", "Arguments: Windows command line or JSON array of strings"); Layout.fillWidth: true }
            TextField { id: launchArguments; objectName: "launchArguments"; maximumLength: 32767; selectByMouse: true; Layout.fillWidth: true }
            Caption { text: window.t("Рабочий каталог", "Working directory"); Layout.fillWidth: true }
            TextField { id: launchDirectory; objectName: "launchDirectory"; maximumLength: 32767; placeholderText: window.t("По умолчанию — каталог EXE", "Default: EXE directory"); selectByMouse: true; Layout.fillWidth: true }
            Label { textFormat: Text.PlainText; text: window.t("JSON должен содержать только строки без NUL.", "JSON must contain only strings without NUL."); color: errorInk; visible: !launchDialog.parsedArguments.valid; wrapMode: Text.Wrap; Layout.fillWidth: true }
            Caption { text: window.t("Запуск проверяет контракт выбранного backend. APP_PROFILE требует совпадения EXE и SHA-256 с адаптером; перенаправленный режим требует runtime.", "Launch checks the selected backend contract. APP_PROFILE requires an exact adapter EXE and SHA-256; redirected mode requires a runtime."); Layout.fillWidth: true }
        }
        footer: RowLayout {
            spacing: 8
            Item { Layout.fillWidth: true }
            Action { objectName: "launchCancel"; text: window.t("Отмена", "Cancel"); onClicked: launchDialog.reject() }
            Action { objectName: "launchConfirm"; text: window.t("Запустить", "Launch"); primary: true; enabled: !backend.busy && launchDialog.sandbox === backend.selected && !!launchExecutable.text && launchDialog.parsedArguments.valid; onClicked: launchDialog.accept() }
        }
    }
    Dialog {
        id: scopeDialog
        objectName: "scopeDialog"
        property string sandboxId
        anchors.centerIn: parent
        width: Math.min(740, window.width - 48)
        height: Math.min(600, window.height - 48)
        modal: true
        focus: true
        title: window.t("Режим и области перенаправления", "Execution mode and redirection scopes")
        standardButtons: Dialog.Ok | Dialog.Cancel
        onOpened: {
            sandboxId = backend.selected
            let p = window.profile
            executionMode.currentIndex = p.executionMode === "app_profile" ? 1 : 0
            fileRoots.text = ((p.redirect || {}).fileRoots || []).join("\n")
            registryRoots.text = ((p.redirect || {}).registryRoots || []).join("\n")
            requireAudit.checked = !!(p.audit || {}).required
            window.applyDialogLanguage(scopeDialog)
            executionMode.forceActiveFocus()
        }
        onAccepted: {
            if (sandboxId !== backend.selected || backend.busy) return
            let p = Object.assign({},window.profile)
            p.executionMode = executionMode.currentText
            p.audit = {required:requireAudit.checked}
            p.redirect = {fileRoots:fileRoots.text.split(/\r?\n/).map(v=>v.trim()).filter(v=>v.length),registryRoots:registryRoots.text.split(/\r?\n/).map(v=>v.trim()).filter(v=>v.length)}
            backend.perform("profile.edit",{profile:p})
        }
        ColumnLayout {
            anchors.fill: parent
            Choice { id: executionMode; objectName: "executionMode"; model: ["usermode_redirected", "app_profile"]; Layout.fillWidth: true }
            CheckBox { id: requireAudit; text: window.t("Требовать системный журнал перед запуском", "Require Windows audit before launch"); Layout.fillWidth: true }
            Caption { text: window.t("Оставьте оба списка пустыми, чтобы перенаправлять всё: все локальные диски и весь реестр (по умолчанию). Иначе — один абсолютный каталог на строку, до 8 областей.", "Leave both lists empty to redirect everything: all local drives and the whole registry (default). Otherwise one absolute directory per line, up to 8 scopes."); Layout.fillWidth: true }
            StableScrollView { Layout.fillWidth: true; Layout.fillHeight: true; TextArea { id: fileRoots; objectName: "fileRoots"; selectByMouse: true; font.family: "Consolas"; wrapMode: TextEdit.NoWrap } }
            Caption { text: window.t("Только для выборочного режима: ключи HKCU\\Software\\… или HKLM\\Software\\…, по одному на строку, до 8.", "Selective mode only: HKCU\\Software\\… or HKLM\\Software\\… keys, one per line, up to 8."); Layout.fillWidth: true }
            StableScrollView { Layout.fillWidth: true; Layout.fillHeight: true; TextArea { id: registryRoots; objectName: "registryRoots"; selectByMouse: true; font.family: "Consolas"; wrapMode: TextEdit.NoWrap } }
            Caption { text: window.t("Для APP_PROFILE настройте точный EXE, SHA-256 и аргумент dataDir через редактор JSON. Системные брокеры, прямые syscalls и чужие handles вне покрытия.", "For APP_PROFILE, configure the exact EXE, SHA-256 and dataDir argument in the JSON editor. System brokers, direct syscalls and foreign handles are outside coverage."); Layout.fillWidth: true }
        }
    }
    FileDialog { id: exePicker; nameFilters: ["Windows EXE (*.exe)"]; onAccepted: backend.perform("application.add",{url:selectedFile.toString()}) }
    FileDialog { id: launchPicker; nameFilters: ["Windows EXE (*.exe)"]; onAccepted: window.openApplicationLaunch(backend.localPath(selectedFile.toString()),"","") }
    FileDialog { id: importPicker; nameFilters: ["JSON (*.json)"]; onAccepted: backend.perform("profile.importFile",{url:selectedFile.toString()}) }
    FileDialog {
        id: exportPicker
        property string kind: "profile"
        property string format: "json"
        fileMode: FileDialog.SaveFile
        defaultSuffix: kind === "profile" ? "json" : format
        onAccepted: backend.perform(kind === "profile" ? "profile.exportFile" : format === "jsonl" ? "events.rawExportFile" : "events.exportFile",{url:selectedFile.toString(),format:format})
    }
    Shortcut { sequence: "F5"; onActivated: backend.perform("refresh") }
    Shortcut { sequence: "Ctrl+N"; onActivated: createDialog.open() }
}
