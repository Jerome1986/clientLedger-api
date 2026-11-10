import { Injectable } from '@nestjs/common'
import { PrismaService } from '../prisma/prisma.service'
import { RegisterAdmin } from './dto/register-admin.dto'
import { Prisma, Role } from '@prisma/client'

@Injectable()
export class AdminRepository {
  constructor(private readonly prisma: PrismaService) {}

  // 按用户名查询登录账号
  findByUsername(username: string) {
    return this.prisma.admin.findUnique({ where: { username } })
  }

  // 查询首个账号标识，用于判断是否需要初始化管理员
  findFirstAccount(tx?: Prisma.TransactionClient) {
    const db = tx ?? this.prisma
    return db.admin.findFirst({ select: { id: true } })
  }

  // 写入初始管理员账号，密码须由 Service 完成哈希处理
  registerAdminAccount(registerDto: RegisterAdmin, tx?: Prisma.TransactionClient) {
    const db = tx ?? this.prisma
    return db.admin.create({
      data: {
        username: registerDto.username,
        password: registerDto.password,
        role: Role.ADMIN
      }
    })
  }
}
