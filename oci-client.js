const common = require('oci-common');
const core = require('oci-core');
const identity = require('oci-identity');
const monitoring = require('oci-monitoring');
const fs = require('fs');
const path = require('path');

class OracleClient {
    constructor(config) {
        // Config: { user, fingerprint, tenancy, region, keyFile }
        
        const keyPath = path.isAbsolute(config.keyFile)
            ? config.keyFile
            : path.join(__dirname, config.keyFile);
        if (!fs.existsSync(keyPath)) {
            throw new Error(`私钥文件不存在: ${keyPath}`);
        }
        let privateKey = fs.readFileSync(keyPath, 'utf8');
        const regionId = String(config.region || '').trim().toLowerCase();
        if (!regionId) {
            throw new Error('Region 不能为空');
        }
        let region;
        try {
            region = common.Region.fromRegionId(regionId);
            if (!region) {
                region = common.Region.register(regionId, common.Realm.OC1);
            }
        } catch (_) {
            region = common.Region.register(regionId, common.Realm.OC1);
        }
        
        // Clean up key content
        privateKey = privateKey.replace(/\r\n/g, '\n').trim();
        if (!privateKey.endsWith('\n')) privateKey += '\n';

        console.log(`[OCI Init] Tenancy: ${config.tenancy}`);
        console.log(`[OCI Init] User: ${config.user}`);
        console.log(`[OCI Init] Fingerprint: ${config.fingerprint}`);
        console.log(`[OCI Init] Region: ${region.regionId}`);
        
        // Correct Constructor Order:
        // tenancy, user, fingerprint, privateKey, passphrase, region
        this.provider = new common.SimpleAuthenticationDetailsProvider(
            config.tenancy,
            config.user,
            config.fingerprint,
            privateKey,
            null, // passphrase
            region // Region object
        );
        
        this.computeClient = new core.ComputeClient({ authenticationDetailsProvider: this.provider });
        this.networkClient = new core.VirtualNetworkClient({ authenticationDetailsProvider: this.provider });
        this.identityClient = new identity.IdentityClient({ authenticationDetailsProvider: this.provider });
        this.monitoringClient = new monitoring.MonitoringClient({ authenticationDetailsProvider: this.provider });
    }

    // 1. 测试连接 (列出可用区)
    async testConnection() {
        try {
            console.log('Testing connection...');
            // Try to get user info first, usually simpler
            const req = { compartmentId: this.provider.getTenantId() };
            const res = await this.identityClient.listAvailabilityDomains(req);
            console.log('Connection success! Domains:', res.items.length);
            return { ok: true, domains: res.items.map(d => d.name) };
        } catch (e) {
            console.error('Connection failed:', e.message);
            console.error('Service Code:', e.serviceCode);
            console.error('Status Code:', e.statusCode);
            
            if (e.statusCode === 401) {
                return { ok: false, error: '认证失败: 请检查 Fingerprint 和私钥是否匹配，或者 User/Tenancy OCID 是否正确。' };
            }
            if (e.statusCode === 404) {
                return { ok: false, error: '资源未找到: 请检查 Region 是否正确，或者 Tenancy OCID 是否正确。' };
            }
            
            return { ok: false, error: e.message };
        }
    }

    // 2. 列出实例
    async listInstances() {
        try {
            const compartmentId = this.provider.getTenantId();
            const req = { compartmentId };
            const res = await this.computeClient.listInstances(req);
            
            const active = res.items.filter(i => i.lifecycleState !== 'TERMINATED');
            const instances = [];
            
            for (const inst of active) {
                const [ip, ipv6] = await Promise.all([
                    this.getPublicIp(inst.id),
                    this.getIpv6(inst.id)
                ]);
                instances.push({
                    id: inst.id,
                    name: inst.displayName,
                    shape: inst.shape,
                    state: inst.lifecycleState,
                    region: inst.region,
                    created: inst.timeCreated,
                    public_ip: ip,
                    ipv6: ipv6
                });
            }
            return instances;
        } catch (e) {
            console.error('List instances failed:', e.message);
            throw e;
        }
    }

    // 2.1 单实例刷新
    async getInstanceById(instanceId) {
        const res = await this.computeClient.getInstance({ instanceId });
        const inst = res.instance;
        if (!inst) throw new Error('Instance not found');
        const [ip, ipv6] = await Promise.all([
            this.getPublicIp(instanceId),
            this.getIpv6(instanceId)
        ]);
        return {
            id: inst.id,
            name: inst.displayName,
            shape: inst.shape,
            state: inst.lifecycleState,
            region: inst.region,
            created: inst.timeCreated,
            public_ip: ip,
            ipv6: ipv6
        };
    }

    // Helper: Get primary VNIC ID
    async getPrimaryVnicId(instanceId) {
        const vnicAttachments = await this.computeClient.listVnicAttachments({
            compartmentId: this.provider.getTenantId(),
            instanceId: instanceId
        });
        if (vnicAttachments.items.length === 0) throw new Error('No VNIC found');
        return vnicAttachments.items[0].vnicId;
    }

    // Helper: Get Public IP
    async getPublicIp(instanceId) {
        try {
            const vnicId = await this.getPrimaryVnicId(instanceId);
            const vnic = await this.networkClient.getVnic({ vnicId });
            return vnic.vnic.publicIp || 'Private Only';
        } catch (e) {
            return 'Error';
        }
    }

    // Helper: Get IPv6 address
    async getIpv6(instanceId) {
        try {
            const vnicId = await this.getPrimaryVnicId(instanceId);
            const res = await this.networkClient.listIpv6s({ vnicId });
            if (res.items.length === 0) return null;
            return res.items[0].ipAddress || null;
        } catch (e) {
            return null;
        }
    }

    // 3. 换 IP
    async changePublicIp(instanceId) {
        try {
            const vnicId = await this.getPrimaryVnicId(instanceId);
            
            const privateIps = await this.networkClient.listPrivateIps({ vnicId });
            if (privateIps.items.length === 0) throw new Error('No Private IP found');
            const primaryPrivateIp = privateIps.items.find(ip => ip.isPrimary) || privateIps.items[0];
            const privateIpId = primaryPrivateIp.id;
            return await this.createOrReplaceEphemeralPublicIp(
                privateIpId,
                primaryPrivateIp.compartmentId || this.provider.getTenantId()
            );
        } catch (e) {
            if (e.statusCode === 404 || e.statusCode === 403) {
                throw new Error('OCI 权限不足或资源不在可访问范围。请给当前用户补充网络权限：manage public-ips、read private-ips、read vnics（实例所在 compartment）。');
            }
            throw e;
        }
    }

    // 4. 换 IPv6
    async changeIpv6(instanceId) {
        try {
            const vnicId = await this.getPrimaryVnicId(instanceId);
            const compartmentId = this.provider.getTenantId();

            // List existing IPv6 addresses on this VNIC
            const existing = await this.networkClient.listIpv6s({ vnicId });
            const oldIpv6s = existing.items.filter(
                ip => ip.lifecycleState !== 'TERMINATED' && ip.lifecycleState !== 'TERMINATING'
            );

            // Delete all existing ephemeral IPv6 addresses
            for (const old of oldIpv6s) {
                await this.networkClient.deleteIpv6({ ipv6Id: old.id });
            }

            // Wait a moment for deletion to propagate
            if (oldIpv6s.length > 0) await this.sleep(2000);

            // Create a new ephemeral IPv6
            const created = await this.networkClient.createIpv6({
                createIpv6Details: {
                    vnicId,
                    lifetime: 'EPHEMERAL'
                }
            });
            return created.ipv6.ipAddress;
        } catch (e) {
            if (e.statusCode === 404 || e.statusCode === 403) {
                throw new Error('OCI 权限不足或子网未启用 IPv6。请确认子网已分配 IPv6 CIDR，并给用户补充 manage ipv6s 权限。');
            }
            throw e;
        }
    }

    // 5. 查询实例本月流量
    async getMonthlyTraffic(instanceId) {
        const compartmentId = this.provider.getTenantId();
        const vnicId = await this.getPrimaryVnicId(instanceId);
        const now = new Date();
        const startTime = new Date(now.getFullYear(), now.getMonth(), 1);

        const queryMetric = async (metricName) => {
            const res = await this.monitoringClient.summarizeMetricsData({
                compartmentId,
                compartmentIdInSubtree: true,
                summarizeMetricsDataDetails: {
                    namespace: 'oci_vcn',
                    query: `${metricName}[1d]{resourceId = "${vnicId}"}.sum()`,
                    startTime,
                    endTime: now,
                    resolution: '1d'
                }
            });
            let total = 0;
            for (const metric of res.items) {
                for (const dp of metric.aggregatedDatapoints || []) {
                    total += dp.value || 0;
                }
            }
            return total;
        };

        const [bytesIn, bytesOut] = await Promise.all([
            queryMetric('VnicFromNetworkBytes'),
            queryMetric('VnicToNetworkBytes')
        ]);

        return { bytesIn, bytesOut };
    }

    async createOrReplaceEphemeralPublicIp(privateIpId, compartmentId) {
        const maxAttempts = 4;
        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                const created = await this.networkClient.createPublicIp({
                    createPublicIpDetails: {
                        compartmentId,
                        lifetime: core.models.CreatePublicIpDetails.Lifetime.Ephemeral,
                        privateIpId
                    }
                });
                return created.publicIp.ipAddress;
            } catch (e) {
                const stuckPublicIpId = this.extractAssignedPublicIpIdFromError(e && e.message);
                console.error('[ChangeIP] createPublicIp failed:', e && e.message);
                console.error('[ChangeIP] parsed stuck publicIpId:', stuckPublicIpId);
                if (!stuckPublicIpId) throw e;
                await this.detachPublicIpById(stuckPublicIpId);
                await this.sleep(1200 * attempt);
            }
        }
        throw new Error('旧公网 IP 解绑后仍无法创建新 IP，请稍后重试。');
    }

    extractAssignedPublicIpIdFromError(message) {
        if (!message) return null;
        const match = message.match(/(ocid1\.publicip\.[a-z0-9._-]+)/i);
        return match ? match[1] : null;
    }

    async detachPublicIpById(publicIpId) {
        const current = await this.networkClient.getPublicIp({ publicIpId });
        const pubIp = current.publicIp;
        if (!pubIp || !pubIp.id) return;
        if (pubIp.lifetime === core.models.PublicIp.Lifetime.Reserved) {
            await this.networkClient.updatePublicIp({
                publicIpId: pubIp.id,
                updatePublicIpDetails: { privateIpId: '' }
            });
        } else {
            await this.networkClient.deletePublicIp({ publicIpId: pubIp.id });
        }
    }

    // 6. 列出可用域
    async listAvailabilityDomains() {
        const res = await this.identityClient.listAvailabilityDomains({
            compartmentId: this.provider.getTenantId()
        });
        return res.items.map(d => d.name);
    }

    // 7. 列出子网
    async listSubnets() {
        const compartmentId = this.provider.getTenantId();
        const vcns = await this.networkClient.listVcns({ compartmentId });
        const subnets = [];
        for (const vcn of vcns.items) {
            const res = await this.networkClient.listSubnets({ compartmentId, vcnId: vcn.id });
            for (const s of res.items) {
                subnets.push({ id: s.id, name: s.displayName, vcnName: vcn.displayName, ad: s.availabilityDomain || 'Regional' });
            }
        }
        return subnets;
    }

    // 8. 列出镜像 (Ubuntu only)
    async listImages(shape) {
        const compartmentId = this.provider.getTenantId();
        const params = { compartmentId, lifecycleState: 'AVAILABLE', operatingSystem: 'Canonical Ubuntu', sortBy: 'TIMECREATED', sortOrder: 'DESC', limit: 50 };
        if (shape) params.shape = shape;
        const res = await this.computeClient.listImages(params);
        return res.items.map(i => ({ id: i.id, name: i.displayName, os: i.operatingSystem, osVersion: i.operatingSystemVersion }));
    }

    // 9. 创建实例（抢机）
    async launchInstance(config) {
        const compartmentId = this.provider.getTenantId();
        const metadata = {};
        if (config.sshPublicKey) metadata.ssh_authorized_keys = config.sshPublicKey;

        // cloud-init to set root password and enable SSH root login
        if (config.rootPassword) {
            metadata.user_data = Buffer.from([
                '#!/bin/bash',
                `echo "root:${config.rootPassword}" | chpasswd`,
                'sed -i "s/^#\\?PermitRootLogin.*/PermitRootLogin yes/" /etc/ssh/sshd_config',
                'sed -i "s/^#\\?PasswordAuthentication.*/PasswordAuthentication yes/" /etc/ssh/sshd_config',
                'systemctl restart sshd'
            ].join('\n')).toString('base64');
        }

        const shapeConfig = {};
        if (config.shape && config.shape.startsWith('VM.Standard.A') || config.shape && config.shape.includes('Flex')) {
            shapeConfig.ocpus = config.ocpus || 1;
            shapeConfig.memoryInGBs = config.memoryGb || 6;
        }

        const launchDetails = {
            compartmentId,
            availabilityDomain: config.availabilityDomain,
            displayName: config.name || 'grabbed-instance',
            shape: config.shape,
            sourceDetails: {
                sourceType: 'image',
                imageId: config.imageId
            },
            createVnicDetails: {
                subnetId: config.subnetId,
                assignPublicIp: true
            },
            metadata
        };
        if (Object.keys(shapeConfig).length > 0) launchDetails.shapeConfig = shapeConfig;

        const res = await this.computeClient.launchInstance({ launchInstanceDetails: launchDetails });
        return { id: res.instance.id, name: res.instance.displayName, state: res.instance.lifecycleState };
    }

    async sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

module.exports = OracleClient;
