/// <reference types="jest" />

import { BadRequestException } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { compare, hash } from 'bcrypt'
import { Prisma, Role } from '@prisma/client'
import { AdminRepository } from './admin.repository'
import { AdminService } from './admin.service'
import { PrismaService } from '../prisma/prisma.service'

// 替换真实密码计算；本文件验证登录流程，不执行真实加密或连接数据库
jest.mock('bcrypt', () => ({ compare: jest.fn(), hash: jest.fn() }))

describe('AdminService.loginPc（PC登录）', () => {
  // 模拟依赖：每个测试可以指定数据库查询、事务和令牌签发的结果
  const findByUsername = jest.fn<Promise<unknown>, unknown[]>()
  const findFirstAccount = jest.fn<Promise<unknown>, unknown[]>()
  const registerAdminAccount = jest.fn<Promise<unknown>, unknown[]>()
  const transaction = jest.fn<
    Promise<void>,
    [callback: (client: Prisma.TransactionClient) => Promise<void>, options?: unknown]
  >()
  const tx = {} as Prisma.TransactionClient
  const signAsync = jest.fn<Promise<string>, unknown[]>()
  const comparePassword = jest.mocked(compare)
  const hashPassword = jest.mocked(hash)
  const adminRepository = {
    findByUsername,
    findFirstAccount,
    registerAdminAccount
  } as unknown as AdminRepository
  const jwtService = { signAsync } as unknown as JwtService
  const prisma = { $transaction: transaction } as unknown as PrismaService
  const service = new AdminService(adminRepository, jwtService, prisma)
  const dto = { username: 'admin', password: '123456' }
  const admin = {
    id: 1,
    username: 'admin',
    password: 'hashed-password',
    role: Role.ADMIN,
    status: true
  }

  // 每个用例开始前重置模拟状态，默认场景为已有账号且密码正确
  beforeEach(() => {
    jest.resetAllMocks()
    findFirstAccount.mockResolvedValue({ id: admin.id })
    findByUsername.mockResolvedValue(admin)
    registerAdminAccount.mockResolvedValue(admin)
    comparePassword.mockResolvedValue(true as never)
    hashPassword.mockResolvedValue('hashed-password' as never)
    signAsync.mockResolvedValue('token')
    transaction.mockImplementation((callback) => callback(tx))
  })

  it('已有账号且密码正确：返回令牌及安全用户信息，不触发初始化', async () => {
    // 执行实际 Service 方法，断言返回值；未列出的密码字段不会被返回
    await expect(service.loginPc(dto)).resolves.toEqual({
      token: 'token',
      userInfo: { id: 1, username: 'admin', role: Role.ADMIN }
    })
    expect(transaction).not.toHaveBeenCalled()
    expect(hashPassword).not.toHaveBeenCalled()
    expect(registerAdminAccount).not.toHaveBeenCalled()
    expect(findByUsername).toHaveBeenCalledWith(dto.username)
    expect(comparePassword).toHaveBeenCalledWith(dto.password, admin.password)
    expect(signAsync).toHaveBeenCalledWith({
      sub: admin.id,
      username: admin.username,
      role: admin.role
    })
    expect(signAsync).toHaveBeenCalledTimes(1)
  })

  it('密码错误：抛出业务异常，不签发令牌', async () => {
    // 安排失败场景：让密码比对返回 false，再验证登录是否拒绝
    comparePassword.mockResolvedValue(false as never)

    await expect(
      service.loginPc({ username: 'admin', password: 'wrong-pass' })
    ).rejects.toBeInstanceOf(BadRequestException)
    expect(signAsync).not.toHaveBeenCalled()
  })

  it.each([
    { scenario: '账号不存在', account: null },
    { scenario: '账号已禁用', account: { ...admin, status: false } }
  ])('$scenario：拒绝登录，不校验密码或签发令牌', async ({ account }) => {
    findByUsername.mockResolvedValue(account)

    await expect(service.loginPc(dto)).rejects.toBeInstanceOf(BadRequestException)
    expect(comparePassword).not.toHaveBeenCalled()
    expect(signAsync).not.toHaveBeenCalled()
  })

  it('首次登录：使用密码哈希及事务客户端创建账号，等待提交后再登录', async () => {
    findFirstAccount.mockResolvedValue(null)
    let commit: () => void = () => undefined
    const committed = new Promise<void>((resolve) => {
      commit = resolve
    })
    let notifyCreated: () => void = () => undefined
    const created = new Promise<void>((resolve) => {
      notifyCreated = resolve
    })
    // 手动控制模拟事务完成时间，检查提交前是否提前执行了登录
    transaction.mockImplementation(async (callback) => {
      await callback(tx)
      notifyCreated()
      await committed
    })

    const result = service.loginPc(dto)
    await created

    expect(hashPassword).toHaveBeenCalledWith(dto.password, 10)
    expect(findFirstAccount).toHaveBeenLastCalledWith(tx)
    expect(transaction).toHaveBeenCalledWith(expect.any(Function), {
      isolationLevel: Prisma.TransactionIsolationLevel.Serializable
    })
    expect(registerAdminAccount).toHaveBeenCalledWith(
      { username: dto.username, password: 'hashed-password' },
      tx
    )
    expect(findByUsername).not.toHaveBeenCalled()
    expect(signAsync).not.toHaveBeenCalled()

    commit()
    await expect(result).resolves.toEqual({
      token: 'token',
      userInfo: { id: admin.id, username: admin.username, role: Role.ADMIN }
    })
    expect(comparePassword).toHaveBeenCalledWith(dto.password, admin.password)
    expect(signAsync).toHaveBeenCalledTimes(1)
  })

  it('哈希期间已有账号创建：事务内复查后跳过创建，继续正常登录', async () => {
    findFirstAccount.mockResolvedValueOnce(null).mockResolvedValueOnce({ id: admin.id })

    await expect(service.loginPc(dto)).resolves.toHaveProperty('token', 'token')
    expect(registerAdminAccount).not.toHaveBeenCalled()
    expect(findByUsername).toHaveBeenCalledWith(dto.username)
  })

  it('初始化事务失败：向外抛出异常，不查询登录账号或签发令牌', async () => {
    findFirstAccount.mockResolvedValue(null)
    const failure = new Error('transaction failed')
    transaction.mockRejectedValue(failure)

    await expect(service.loginPc(dto)).rejects.toThrow(failure)
    expect(findByUsername).not.toHaveBeenCalled()
    expect(signAsync).not.toHaveBeenCalled()
  })
})
