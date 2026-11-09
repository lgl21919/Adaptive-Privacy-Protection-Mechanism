'use strict';

const { WorkloadModuleBase } = require('@hyperledger/caliper-core');

/**
 * Academic Publishing Workload Module
 */
class AcademicPublishingWorkload extends WorkloadModuleBase {
    constructor() {
        super();
        this.paperIDs = [];
        this.policyIDs = [];
    }

    /**
     * 初始化工作负载模块
     */
    async initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext) {
        await super.initializeWorkloadModule(workerIndex, totalWorkers, roundIndex, roundArguments, sutAdapter, sutContext);

        console.log(`Worker ${this.workerIndex}: 初始化工作负载模块`);

        // 初始化阶段：存储数据保护策略
        const policyCount = this.roundArguments.policyCount || 5;
        for (let i = 0; i < policyCount; i++) {
            const policyID = `policy_REVIEW_MANUSCRIPT_${this.workerIndex}_${i}`;
            this.policyIDs.push(policyID);
            
            const request = {
                contractId: this.roundArguments.contractId,
                contractFunction: 'StoreDataProtectionPolicy',
                invokerIdentity: 'User1',
                contractArguments: [
                    policyID,  // policyID
                    'REVIEW',   // phase
                    'MANUSCRIPT', // dataType
                    'ECDH_HKDF', // policyType
                    `审稿阶段论文数据Level1加密策略_${i}`, // description
                    'User1',    // createdBy
                    '1'         // securityLevel (string, will be converted to int in chaincode)
                ],
                readOnly: false
            };

            try {
                await this.sutAdapter.sendRequests(request);
                console.log(`Worker ${this.workerIndex}: 已存储策略 ${policyID}`);
            } catch (error) {
                console.error(`Worker ${this.workerIndex}: 存储策略失败 ${policyID}:`, error.message);
            }
        }

        // 初始化阶段：创建一些加密论文
        const paperCount = this.roundArguments.paperCount || 10;
        for (let i = 0; i < paperCount; i++) {
            const paperID = `paper_${this.workerIndex}_${i}_${Date.now()}`;
            this.paperIDs.push(paperID);
            
            // 创建加密论文JSON（简化版本，实际应该包含完整的EncryptedPaper结构）
            const encryptedPaper = {
                PaperID: paperID,
                Version: 1,
                Title: `测试论文标题_${i}`,
                Abstract: `测试论文摘要_${i}`,
                ContentHash: `hash_${paperID}`,
                AuthorID: `author_${this.workerIndex}`,
                AuthorIdentity: 'User1@org1.example.com',
                fromUserID: `editor_${this.workerIndex}`,
                FromIdentity: 'User1@org1.example.com',
                toUserIDs: [`author_${this.workerIndex}`, `reviewer_${this.workerIndex}`],
                ToIdentities: ['User1@org1.example.com', 'User1@org1.example.com'],
                l1_content: Buffer.from(`加密内容_${paperID}`).toString('base64'),
                l1_encrypted: true,
                l1_encryption_type: 'ECDH_HKDF',
                l2_content: {
                    [`author_${this.workerIndex}`]: Buffer.from(`重加密密钥_author_${paperID}`).toString('base64'),
                    [`reviewer_${this.workerIndex}`]: Buffer.from(`重加密密钥_reviewer_${paperID}`).toString('base64')
                },
                l2_encrypted: true,
                l2_encryption_type: 'PROXY_REENCRYPTION',
                data_type: 'MANUSCRIPT',
                security_level: 1,
                Status: 'UNDER_REVIEW',
                Phase: 'REVIEW',
                SubmittedAt: new Date().toISOString(),
                UpdatedAt: new Date().toISOString(),
                Metadata: {
                    'createdBy': 'CaliperTest',
                    'testType': 'performance'
                },
                AccessControl: {}
            };

            const request = {
                contractId: this.roundArguments.contractId,
                contractFunction: 'StoreEncryptedPaper',
                invokerIdentity: 'User1',
                contractArguments: [JSON.stringify(encryptedPaper)],
                readOnly: false
            };

            try {
                await this.sutAdapter.sendRequests(request);
                console.log(`Worker ${this.workerIndex}: 已存储加密论文 ${paperID}`);
            } catch (error) {
                console.error(`Worker ${this.workerIndex}: 存储加密论文失败 ${paperID}:`, error.message);
            }
        }

        console.log(`Worker ${this.workerIndex}: 初始化完成，已创建 ${policyCount} 个策略和 ${paperCount} 个论文`);
    }

    /**
     * 提交事务 - 根据配置执行不同的测试场景
     */
    async submitTransaction() {
        const testType = this.roundArguments.testType || 'mixed';
        let request;

        switch (testType) {
            case 'storePolicy':
                // 测试场景1: 存储数据保护策略
                request = this.createStorePolicyRequest();
                break;
            
            case 'storePaper':
                // 测试场景2: 存储加密论文
                request = this.createStorePaperRequest();
                break;
            
            case 'getPaper':
                // 测试场景3: 获取加密论文
                request = this.createGetPaperRequest();
                break;
            
            case 'getPolicy':
                // 测试场景4: 获取数据保护策略
                request = this.createGetPolicyRequest();
                break;
            
            case 'getReKey':
                // 测试场景5: 获取重加密密钥
                request = this.createGetReKeyRequest();
                break;
            
            case 'mixed':
            default:
                // 混合测试场景：随机选择操作类型
                const operations = ['storePaper', 'getPaper', 'getPolicy', 'getReKey'];
                const randomOp = operations[Math.floor(Math.random() * operations.length)];
                
                switch (randomOp) {
                    case 'storePaper':
                        request = this.createStorePaperRequest();
                        break;
                    case 'getPaper':
                        request = this.createGetPaperRequest();
                        break;
                    case 'getPolicy':
                        request = this.createGetPolicyRequest();
                        break;
                    case 'getReKey':
                        request = this.createGetReKeyRequest();
                        break;
                }
                break;
        }

        if (request) {
            await this.sutAdapter.sendRequests(request);
        }
    }

    /**
     * 创建存储数据保护策略的请求
     */
    createStorePolicyRequest() {
        const policyID = `policy_REVIEW_MANUSCRIPT_${this.workerIndex}_${Date.now()}`;
        return {
            contractId: this.roundArguments.contractId,
            contractFunction: 'StoreDataProtectionPolicy',
            invokerIdentity: 'User1',
            contractArguments: [
                policyID,  // policyID
                'REVIEW',   // phase
                'MANUSCRIPT', // dataType
                'ECDH_HKDF', // policyType
                `审稿阶段论文数据Level1加密策略_${Date.now()}`, // description
                'User1',    // createdBy
                '1'         // securityLevel (string, will be converted to int in chaincode)
            ],
            readOnly: false
        };
    }

    /**
     * 创建存储加密论文的请求
     */
    createStorePaperRequest() {
        const paperID = `paper_${this.workerIndex}_${Date.now()}`;
        const encryptedPaper = {
            PaperID: paperID,
            Version: 1,
            Title: `测试论文标题_${Date.now()}`,
            Abstract: `测试论文摘要_${Date.now()}`,
            ContentHash: `hash_${paperID}`,
            AuthorID: `author_${this.workerIndex}`,
            AuthorIdentity: 'User1@org1.example.com',
            fromUserID: `editor_${this.workerIndex}`,
            FromIdentity: 'User1@org1.example.com',
            toUserIDs: [`author_${this.workerIndex}`, `reviewer_${this.workerIndex}`],
            ToIdentities: ['User1@org1.example.com', 'User1@org1.example.com'],
            l1_content: Buffer.from(`加密内容_${paperID}`).toString('base64'),
            l1_encrypted: true,
            l1_encryption_type: 'ECDH_HKDF',
            l2_content: {
                [`author_${this.workerIndex}`]: Buffer.from(`重加密密钥_author_${paperID}`).toString('base64'),
                [`reviewer_${this.workerIndex}`]: Buffer.from(`重加密密钥_reviewer_${paperID}`).toString('base64')
            },
            l2_encrypted: true,
            l2_encryption_type: 'PROXY_REENCRYPTION',
            data_type: 'MANUSCRIPT',
            security_level: 1,
            Status: 'UNDER_REVIEW',
            Phase: 'REVIEW',
            SubmittedAt: new Date().toISOString(),
            UpdatedAt: new Date().toISOString(),
            Metadata: {
                'createdBy': 'CaliperTest',
                'testType': 'performance'
            },
            AccessControl: {}
        };

        return {
            contractId: this.roundArguments.contractId,
            contractFunction: 'StoreEncryptedPaper',
            invokerIdentity: 'User1',
            contractArguments: [JSON.stringify(encryptedPaper)],
            readOnly: false
        };
    }

    /**
     * 创建获取加密论文的请求
     */
    createGetPaperRequest() {
        if (this.paperIDs.length === 0) {
            // 如果没有已创建的论文，创建一个新的
            return this.createStorePaperRequest();
        }
        
        const randomIndex = Math.floor(Math.random() * this.paperIDs.length);
        const paperID = this.paperIDs[randomIndex];
        
        return {
            contractId: this.roundArguments.contractId,
            contractFunction: 'GetEncryptedPaper',
            invokerIdentity: 'User1',
            contractArguments: [paperID],
            readOnly: true
        };
    }

    /**
     * 创建获取数据保护策略的请求
     */
    createGetPolicyRequest() {
        return {
            contractId: this.roundArguments.contractId,
            contractFunction: 'GetDataProtectionPolicy',
            invokerIdentity: 'User1',
            contractArguments: [
                'REVIEW',
                'MANUSCRIPT',
                '1'  // securityLevel (string, will be converted to int in chaincode)
            ],
            readOnly: true
        };
    }

    /**
     * 创建获取重加密密钥的请求
     */
    createGetReKeyRequest() {
        if (this.paperIDs.length === 0) {
            // 如果没有已创建的论文，创建一个新的
            return this.createStorePaperRequest();
        }
        
        const randomIndex = Math.floor(Math.random() * this.paperIDs.length);
        const paperID = this.paperIDs[randomIndex];
        const userID = `author_${this.workerIndex}`;
        
        return {
            contractId: this.roundArguments.contractId,
            contractFunction: 'GetReEncryptionKey',
            invokerIdentity: 'User1',
            contractArguments: [paperID, userID],
            readOnly: true
        };
    }

    /**
     * 清理工作负载模块
     */
    async cleanupWorkloadModule() {
        console.log(`Worker ${this.workerIndex}: 清理工作负载模块`);
    }
}

/**
 * 创建工作负载模块实例
 */
function createWorkloadModule() {
    return new AcademicPublishingWorkload();
}

module.exports.createWorkloadModule = createWorkloadModule;
