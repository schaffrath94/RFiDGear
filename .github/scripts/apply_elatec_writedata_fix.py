from pathlib import Path

ELATEC_PROVIDER = Path("RFiDGear/Infrastructure/ReaderProviders/ElatecNetProvider.cs")
DESFIRE_VIEWMODEL = Path("RFiDGear/ViewModels/TaskSetupViewModels/MifareDesfireSetupViewModel.cs")


def replace_between(path: Path, start_marker: str, end_marker: str, replacement: str) -> None:
    text = path.read_text(encoding="utf-8-sig")

    start_count = text.count(start_marker)
    if start_count != 1:
        raise RuntimeError(
            f"Expected exactly one start marker in {path}, found {start_count}: {start_marker!r}"
        )

    start = text.index(start_marker)
    end = text.index(end_marker, start)
    updated = text[:start] + replacement + text[end:]
    path.write_text(updated, encoding="utf-8")


def replace_through_marker(path: Path, start_marker: str, end_marker: str, replacement: str) -> None:
    text = path.read_text(encoding="utf-8-sig")

    start_count = text.count(start_marker)
    if start_count != 1:
        raise RuntimeError(
            f"Expected exactly one start marker in {path}, found {start_count}: {start_marker!r}"
        )

    start = text.index(start_marker)
    end = text.index(end_marker, start) + len(end_marker)
    updated = text[:start] + replacement + text[end:]
    path.write_text(updated, encoding="utf-8")


replace_between(
    ELATEC_PROVIDER,
    "        public async override Task<ERROR> WriteMiFareDESFireChipFile(",
    "        #endregion",
    """        public async override Task<ERROR> WriteMiFareDESFireChipFile(string _appWriteKey, DESFireKeyType _keyTypeAppWriteKey, int _writeKeyNo,
                                        EncryptionMode _encMode,
                                        int _fileNo, int _appID, byte[] _data)
        {
            try
            {
                await readerDevice.MifareDesfire_SelectApplicationAsync((uint)_appID);

                var authResult = await AuthToMifareDesfireApplication(
                    _appWriteKey,
                    _keyTypeAppWriteKey,
                    _writeKeyNo,
                    _appID);

                if (authResult != ERROR.NoError)
                {
                    return authResult;
                }

                await readerDevice.MifareDesfire_WriteDataAsync(
                    (byte)_fileNo,
                    _data,
                    (Elatec.NET.Cards.Mifare.EncryptionMode)_encMode);

                return ERROR.NoError;
            }
            catch (Exception e)
            {
                Log.ForContext<ElatecNetProvider>().Error(e, "Elatec operation failed.");
                return ERROR.AuthFailure;
            }
        }

""",
)

replace_through_marker(
    DESFIRE_VIEWMODEL,
    "                            if (SelectedDesfireFileType == FileType_MifareDesfireFileType.BackupFile && device.GetType() == typeof(ElatecNetProvider))",
    "                            if (result == ERROR.NoError)",
    """                            if (result == ERROR.NoError &&
                                SelectedDesfireFileType == FileType_MifareDesfireFileType.BackupFile &&
                                device.GetType() == typeof(ElatecNetProvider))
                            {
                                result = await device.CommitTransactionAsync();
                            }

                            if (result == ERROR.NoError)""",
)
