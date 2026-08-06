using System.Threading.Tasks;
using Elatec.NET.Cards.Mifare;
using RFiDGear.Infrastructure;
using RFiDGear.Infrastructure.ReaderProviders;
using Xunit;
using RfidEncryptionMode = RFiDGear.Infrastructure.EncryptionMode;
using DESFireKeyType = RFiDGear.Infrastructure.DESFireKeyType;

namespace RFiDGear.Tests
{
    public class ElatecNetProviderTests
    {
        [Fact]
        public void ResolveKeyTypeForChange_PiccUsesTargetKeyType()
        {
            var result = ElatecNetProvider.ResolveKeyTypeForChange(
                appId: 0,
                targetKeyType: DESFireKeyType.DF_KEY_AES,
                detectedKeyType: DESFireKeyType.DF_KEY_DES);

            Assert.Equal(DESFireKeyType.DF_KEY_AES, result);
        }

        [Fact]
        public void ResolveKeyTypeForChange_AppUsesDetectedKeyTypeWhenAvailable()
        {
            var result = ElatecNetProvider.ResolveKeyTypeForChange(
                appId: 1,
                targetKeyType: DESFireKeyType.DF_KEY_AES,
                detectedKeyType: DESFireKeyType.DF_KEY_DES);

            Assert.Equal(DESFireKeyType.DF_KEY_DES, result);
        }

        [Fact]
        public void ResolveKeyTypeForChange_AppFallsBackToTargetWhenUnknown()
        {
            var result = ElatecNetProvider.ResolveKeyTypeForChange(
                appId: 1,
                targetKeyType: DESFireKeyType.DF_KEY_AES,
                detectedKeyType: null);

            Assert.Equal(DESFireKeyType.DF_KEY_AES, result);
        }

        [Fact]
        public void ResolveDesfireKeyType_UsesProviderNameWhenKnown()
        {
            var result = ElatecNetProvider.ResolveDesfireKeyType("DF_KEY_AES", DESFireKeyType.DF_KEY_DES);

            Assert.Equal(DESFireKeyType.DF_KEY_AES, result);
        }

        [Fact]
        public void ResolveDesfireKeyType_FallsBackWhenUnknown()
        {
            var result = ElatecNetProvider.ResolveDesfireKeyType("UnknownKeyType", DESFireKeyType.DF_KEY_3K3DES);

            Assert.Equal(DESFireKeyType.DF_KEY_3K3DES, result);
        }

        [Fact]
        public async Task CreateMifareDesfireFile_BackupFile_UsesBackupCreatePath()
        {
            var provider = new BackupFileTestProvider();
            var accessRights = new DESFireAccessRights
            {
                readAccess = TaskAccessRights.AR_KEY0,
                writeAccess = TaskAccessRights.AR_KEY1,
                readAndWriteAccess = TaskAccessRights.AR_KEY2,
                changeAccess = TaskAccessRights.AR_KEY3
            };

            var result = await provider.CreateMifareDesfireFile(
                _appMasterKey: "0000000000000000",
                _keyTypeAppMasterKey: DESFireKeyType.DF_KEY_AES,
                _fileType: Infrastructure.Tasks.FileType_MifareDesfireFileType.BackupFile,
                _accessRights: accessRights,
                _encMode: RfidEncryptionMode.CM_PLAIN,
                _appID: 1,
                _fileNo: 2,
                _fileSize: 16);

            Assert.Equal(ERROR.NoError, result);
            Assert.True(provider.BackupFileRequested);
            Assert.False(provider.StdDataFileRequested);
        }

        [Fact]
        public async Task ReadMiFareDESFireChipFile_WhenReaderRejectsAccess_ReturnsPermissionDenied()
        {
            var provider = new AccessDeniedReadTestProvider();

            var result = await provider.ReadMiFareDESFireChipFile(
                _appReadKey: "00000000000000000000000000000000",
                _keyTypeAppReadKey: DESFireKeyType.DF_KEY_AES,
                _readKeyNo: 0,
                _encMode: RfidEncryptionMode.CM_ENCRYPT,
                _fileNo: 3,
                _appID: 16024277,
                _fileSize: 32);

            Assert.Equal(ERROR.PermissionDenied, result);
        }

        private sealed class AccessDeniedReadTestProvider : ElatecNetProvider
        {
            public override Task<ERROR> AuthToMifareDesfireApplication(string _applicationMasterKey, DESFireKeyType _keyType, int _keyNumber, int _appID)
            {
                return Task.FromResult(ERROR.NoError);
            }

            protected override Task<byte[]> ReadMifareDesfireDataAsync(byte fileNo, int fileSize, RfidEncryptionMode encryptionMode)
            {
                throw new System.Exception("AccessDenied");
            }
        }
        [Fact]
        public async Task CreateMifareDesfireFile_WhenAuthenticationFails_ReturnsAuthenticationError()
        {
            var provider = new AuthenticationFailureCreateFileProvider();

            var result = await provider.CreateMifareDesfireFile(
                _appMasterKey: "0000000000000000",
                _keyTypeAppMasterKey: DESFireKeyType.DF_KEY_DES,
                _fileType: Infrastructure.Tasks.FileType_MifareDesfireFileType.StdDataFile,
                _accessRights: new DESFireAccessRights(),
                _encMode: RfidEncryptionMode.CM_PLAIN,
                _appID: 1,
                _fileNo: 1,
                _fileSize: 16);

            Assert.Equal(ERROR.AuthFailure, result);
        }

        private sealed class AuthenticationFailureCreateFileProvider : ElatecNetProvider
        {
            public override bool IsConnected => true;

            public override Task<ERROR> AuthToMifareDesfireApplication(string _applicationMasterKey, DESFireKeyType _keyType, int _keyNumber, int _appID)
            {
                return Task.FromResult(ERROR.AuthFailure);
            }
        }
        private sealed class BackupFileTestProvider : ElatecNetProvider
        {
            public bool BackupFileRequested { get; private set; }

            public bool StdDataFileRequested { get; private set; }

            public override bool IsConnected => true;

            public override Task<ERROR> AuthToMifareDesfireApplication(string _applicationMasterKey, DESFireKeyType _keyType, int _keyNumber, int _appID)
            {
                return Task.FromResult(ERROR.NoError);
            }

            protected override Task CreateStdDataFileAsync(byte fileNo, Infrastructure.Tasks.FileType_MifareDesfireFileType fileType, RfidEncryptionMode encMode, DESFireFileAccessRights accessRights, uint fileSize)
            {
                StdDataFileRequested = true;
                return Task.CompletedTask;
            }

            protected override Task CreateBackupFileAsync(byte fileNo, RfidEncryptionMode encMode, DESFireFileAccessRights accessRights, uint fileSize)
            {
                BackupFileRequested = true;
                return Task.CompletedTask;
            }
        }
    }
}
