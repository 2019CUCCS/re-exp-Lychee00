#include <windows.h>
// Global variable

HINSTANCE hinst;

// Function prototypes.

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int);
InitApplication(HINSTANCE);
InitInstance(HINSTANCE, int);
LRESULT CALLBACK MainWndProc(HWND, UINT, WPARAM, LPARAM);
BOOL DoFileOpenSave(HWND hwnd, BOOL bSave);

#define IDM_EDUNDO  0
#define IDM_EDCUT   1
#define IDM_EDCOPY  2
#define IDM_EDPASTE 3
#define IDM_EDDEL   4
#define IDM_ABOUT   5
#define IDM_OPEN    6
#define IDM_SAVE    7
#define IDC_MAIN_TEXT   1001

// Application entry point.

int WINAPI WinMain(HINSTANCE hinstance, HINSTANCE hPrevInstance,
    LPSTR lpCmdLine, int nCmdShow)
{
    MSG msg;

    if (!InitApplication(hinstance))
        return FALSE;

    if (!InitInstance(hinstance, nCmdShow))
        return FALSE;

    BOOL fGotMessage;
    while ((fGotMessage = GetMessage(&msg, (HWND)NULL, 0, 0)) != 0 && fGotMessage != -1)
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return msg.wParam;
    UNREFERENCED_PARAMETER(lpCmdLine);
}

BOOL InitApplication(HINSTANCE hinstance)
{
    WNDCLASSEX wcx;

    // Fill in the window class structure with parameters
    // that describe the main window.

    wcx.cbSize = sizeof(wcx);          // size of structure
    wcx.style = CS_HREDRAW |
        CS_VREDRAW;                    // redraw if size changes
    wcx.lpfnWndProc = MainWndProc;     // points to window procedure
    wcx.cbClsExtra = 0;                // no extra class memory
    wcx.cbWndExtra = 0;                // no extra window memory
    wcx.hInstance = hinstance;         // handle to instance
    wcx.hIcon = LoadIcon(NULL,
        IDI_APPLICATION);              // predefined app. icon
    wcx.hCursor = LoadCursor(NULL,
        IDC_ARROW);                    // predefined arrow
    wcx.hbrBackground = GetStockObject(
        WHITE_BRUSH);                  // white background brush
    wcx.lpszMenuName = "MainMenu";    // name of menu resource
    wcx.lpszClassName = "MainWClass";  // name of window class
    wcx.hIconSm = LoadImage(hinstance, // small class icon
        MAKEINTRESOURCE(5),
        IMAGE_ICON,
        GetSystemMetrics(SM_CXSMICON),
        GetSystemMetrics(SM_CYSMICON),
        LR_DEFAULTCOLOR);

    // Register the window class.

    return RegisterClassEx(&wcx);
}

BOOL InitInstance(HINSTANCE hinstance, int nCmdShow)
{
    HWND hwnd;

    // Save the application-instance handle.

    hinst = hinstance;

    // Create the main window.

    hwnd = CreateWindow(
        "MainWClass",        // name of window class
        L"中国传媒大学",            // title-bar string
        WS_OVERLAPPEDWINDOW, // top-level window
        0,       // default horizontal position
        0,       // default vertical position
        800,       // default width
        500,       // default height
        (HWND)NULL,         // no owner window
        (HMENU)NULL,        // use class menu
        hinstance,           // handle to application instance
        (LPVOID)NULL);      // no window-creation data

    if (!hwnd)
        return FALSE;

    // Show the window and send a WM_PAINT message to the window
    // procedure.

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    return TRUE;

}

#define ID_EDITCHILD 100
HWND hwndEdit;

LRESULT CALLBACK MainWndProc(HWND hwnd,      // window handle
    UINT message,   // type of message
    WPARAM wParam,  // additional information
    LPARAM lParam)  // additional information
{
    HMENU hMenu;

    CHAR lpszLatin[] = "教学案例";

    switch (message)
    {
    case WM_CREATE:

        hMenu = CreateMenu();
        if (hMenu != NULL)
        {
            InsertMenuA(hMenu, -1, MF_BYPOSITION, IDM_EDUNDO, "撤销");
            InsertMenuA(hMenu, -1, MF_BYPOSITION, IDM_EDCUT, "剪切");
            InsertMenuA(hMenu, -1, MF_BYPOSITION, IDM_EDCOPY, "复制");
            InsertMenuA(hMenu, -1, MF_BYPOSITION, IDM_EDPASTE, "粘贴");
            InsertMenuA(hMenu, -1, MF_BYPOSITION, IDM_EDDEL, "删除");
            InsertMenuA(hMenu, -1, MF_BYPOSITION, IDM_ABOUT, "关于");
            InsertMenuA(hMenu, -1, MF_BYPOSITION, IDM_OPEN, "打开");
            InsertMenuA(hMenu, -1, MF_BYPOSITION, IDM_SAVE, "保存");

            SetMenu(hwnd, hMenu);
        }
        hwndEdit = CreateWindowEx(
            0, L"EDIT",   // predefined class
            NULL,         // no window title
            WS_CHILD | WS_VISIBLE | WS_VSCROLL |
            ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL,
            0, 0, 200, 100,   // set size in WM_SIZE message
            hwnd,         // parent window
            (HMENU)ID_EDITCHILD,   // edit control ID
            (HINSTANCE)GetWindowLongPtr(hwnd, GWLP_HINSTANCE),
            NULL);        // pointer not needed

                          // Add text to the window.
        SendMessageA(hwndEdit, WM_SETTEXT, 0, (LPARAM)lpszLatin);

        return 0;

    case WM_COMMAND:
        switch (wParam)
        {
        case IDM_EDUNDO:
            // Send WM_UNDO only if there is something to be undone.

            if (SendMessage(hwndEdit, EM_CANUNDO, 0, 0))
                SendMessage(hwndEdit, WM_UNDO, 0, 0);
            else
            {
                MessageBox(hwndEdit,
                    "Nothing to undo.",
                    "Undo notification",
                    MB_OK);
            }
            break;

        case IDM_EDCUT:
            SendMessage(hwndEdit, WM_CUT, 0, 0);
            break;

        case IDM_EDCOPY:
            SendMessage(hwndEdit, WM_COPY, 0, 0);
            break;

        case IDM_EDPASTE:
            SendMessage(hwndEdit, WM_PASTE, 0, 0);
            break;

        case IDM_EDDEL:
            SendMessage(hwndEdit, WM_CLEAR, 0, 0);
            break;

        case IDM_ABOUT:
            MessageBoxA(hwnd, "教学案例1.0", "教学案例1.0", MB_OK);
            break;

        case IDM_OPEN:
            DoFileOpenSave(hwndEdit, FALSE);
            break;
        case IDM_SAVE:
            DoFileOpenSave(hwndEdit, TRUE);
            break;
        default:
            return DefWindowProcA(hwnd, message, wParam, lParam);
        }
        break;

    case WM_SETFOCUS:
        SetFocus(hwndEdit);
        return 0;

    case WM_SIZE:
        // Make the edit control the size of the window's client area.

        MoveWindow(hwndEdit,
            0, 0,                  // starting x- and y-coordinates
            LOWORD(lParam),        // width of client area
            HIWORD(lParam),        // height of client area
            TRUE);                 // repaint window
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProc(hwnd, message, wParam, lParam);
    }
    return 0;
}


BOOL LoadFile(HWND hEdit, LPSTR pszFileName)
{
    HANDLE pFile;
    pFile = CreateFileA(pszFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0,0);
    DWORD dwBytesRead, dwBytesToRead;
    DWORD fileSize;
    BOOL bsuccess = FALSE;

    if (pFile == INVALID_HANDLE_VALUE) {
        CloseHandle(pFile);
        return bsuccess;
    }
    fileSize = GetFileSize(pFile, NULL);
    LPSTR pszFileText;
    pszFileText = (LPSTR)GlobalAlloc(GPTR, fileSize);
    dwBytesToRead = fileSize;
    dwBytesRead = 0;
    if (ReadFile(pFile, pszFileText, dwBytesToRead, &dwBytesRead, NULL)) {
        pszFileText[dwBytesToRead] = 0;
        if (SetWindowTextA(hEdit, pszFileText)) {
            bsuccess = TRUE;
        }
    }
    GlobalFree(pszFileText);
    CloseHandle(pFile);
    return bsuccess;
}



BOOL SaveFile(HWND hEdit, LPSTR pszFileName)
{
    HANDLE hFile;
    BOOL bSuccess = FALSE;
    hFile = CreateFileA(pszFileName, GENERIC_WRITE, 0, 0,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    
    if (hFile != INVALID_HANDLE_VALUE)
    {
        DWORD dwTextLength;
        dwTextLength = GetWindowTextLengthA(hEdit);
        if (dwTextLength > 0)
        {
            LPSTR pszText;
            pszText = (LPSTR)GlobalAlloc(GPTR, dwTextLength + 1);
            if (pszText != NULL)
            {
                if (GetWindowTextA(hEdit, pszText, dwTextLength + 1))
                {
                    DWORD dwWritten;
                    if (WriteFile(hFile, pszText, dwTextLength, &dwWritten, NULL))
                        bSuccess = TRUE;
                }
                GlobalFree(pszText);
            }
        }
        CloseHandle(hFile);
    }
    return bSuccess;
}

BOOL DoFileOpenSave(HWND hwnd, BOOL bSave)
{
    OPENFILENAME ofn;
    char szFileName[MAX_PATH];

    ZeroMemory(&ofn, sizeof(ofn));
    szFileName[0] = 0;

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = "文本文件 (*.txt)\0*.txt\0所有文件 (*.*)\0*.*\0\0";
    ofn.lpstrFile = szFileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = "txt";

    if (bSave)
    {
        ofn.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY |
            OFN_OVERWRITEPROMPT;

        if (GetSaveFileNameA(&ofn))
        {
            GetDlgItem(hwnd, IDM_SAVE);
            if (!SaveFile(hwnd, szFileName))
            {
                MessageBoxA(hwnd, "保存文件失败", "错误",
                    MB_OK | MB_ICONEXCLAMATION);
                return FALSE;
            }
        }
    }
    else
    {
        ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
        if (GetOpenFileNameA(&ofn))
        {
            GetDlgItem(hwnd,IDM_OPEN);
            if (!LoadFile(hwnd,szFileName))
            {
                MessageBoxA(hwnd, "文件加载失败", "错误",
                    MB_OK | MB_ICONEXCLAMATION);
                return FALSE;
            }
        }
    }
    return TRUE;
}
