import { BadRequestException, Injectable } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import * as bcrypt from 'bcrypt'
import { AdminRepository } from './admin.repository'
import { LoginAdminDto } from './dto/login-admin.dto'
import { Prisma, Role } from '@prisma/client'
import { PrismaService } from '../prisma/prisma.service'

@Injectable()
export class AdminService {
  constructor(
    private readonly adminRepository: AdminRepository,
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService
  ) { }

  // PC账号登录，无账号时先完成管理员初始化
  async loginPc(dto: LoginAdminDto) {
    // 1.检查并初始化管理员
    await this.initializeAdminIfNeeded(dto)

    // 2.已有管理员则直接登录
    const admin = await this.adminRepository.findByUsername(dto.username)
    if (!admin || !admin.status) {
      throw new BadRequestException('账号不存在或已禁用')
    }
    const passwordMatched = await bcrypt.compare(dto.password, admin.password)
    if (!passwordMatched) {
      throw new BadRequestException('密码错误')
    }

    const token = await this.generateToken(admin.id, admin.username, admin.role)

    return {
      token,
      userInfo: {
        id: admin.id,
        username: admin.username,
        role: admin.role
      }
    }
  }

  // 无账号时初始化管理员，密码哈希在事务外计算
  private async initializeAdminIfNeeded(dto: LoginAdminDto): Promise<void> {
    // 查询当前数据库是否有账号
    const existingAccount = await this.adminRepository.findFirstAccount()
    if (existingAccount) {
      return
    }

    // 密码加密
    const hashedPassword = await bcrypt.hash(dto.password, 10)
    await this.prisma.$transaction(async (tx: Prisma.TransactionClient) => {
      // 哈希计算期间可能已有账号创建--重查
      const existingAccount = await this.adminRepository.findFirstAccount(tx)
      if (existingAccount) {
        return
      }

      // 使用Serializable配合P2034 重试处理事务写入冲突与死锁
      await this.adminRepository.registerAdminAccount(
        { username: dto.username, password: hashedPassword },
        tx
      )
    },
      {
        isolationLevel: Prisma.TransactionIsolationLevel.Serializable
      }
    )
  }

  // 为已通过登录校验的账号签发身份令牌
  private async generateToken(id: number, username: string, role: Role) {
    return this.jwtService.signAsync({
      sub: id,
      username,
      role
    })
  }
}
